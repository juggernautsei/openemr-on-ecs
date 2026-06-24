"""Network component — VPC, security groups, shared ALB, WAF WebACL.

Owns all L3/L4 network resources that are shared across every tenant.
"""

from typing import Optional

from aws_cdk import Fn, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_elasticloadbalancingv2 as elb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_wafv2 as wafv2
from cdk_nag import NagSuppressions
from constructs import Construct

from ..constants import (
    CONTAINER_PORT,
    SSM_ALB_ARN,
    SSM_ALB_DNS,
    SSM_ALB_HOSTED_ZONE,
    SSM_ALB_SG_ID,
    SSM_AURORA_SG_ID,
    SSM_CONTAINER_SG_ID,
    SSM_HTTPS_LISTENER_ARN,
    SSM_PRIVATE_SUBNETS,
    SSM_VALKEY_SG_ID,
    SSM_VPC_ID,
    VPC_CIDR,
)


class NetworkComponents:
    """Creates shared VPC, security groups, ALB, and WAF WebACL.

    Build order (all called from SharedInfraStack.__init__):
      1. create_vpc()
      2. create_security_groups()
      3. create_alb(vpc, alb_sg, log_bucket)
      4. add_https_listener(alb, certificate)
      5. create_waf(alb)
    """

    def __init__(self, scope: Construct) -> None:
        self.scope = scope

        # Set by create_vpc()
        self.vpc: Optional[ec2.Vpc] = None

        # Set by create_security_groups()
        self.alb_sg:    Optional[ec2.SecurityGroup] = None
        self.aurora_sg: Optional[ec2.SecurityGroup] = None
        self.valkey_sg: Optional[ec2.SecurityGroup] = None
        self.ecs_sg:    Optional[ec2.SecurityGroup] = None  # baseline; tenants add own SGs

        # Set by create_alb()
        self.alb:        Optional[elb.ApplicationLoadBalancer] = None
        self.log_bucket: Optional[s3.Bucket] = None

        # Set by add_https_listener()
        self.https_listener: Optional[elb.ApplicationListener] = None

        # Set by create_waf()
        self.waf_acl: Optional[wafv2.CfnWebACL] = None

    # ── VPC ────────────────────────────────────────────────────────────────────

    def create_vpc(self, kms_key: kms.Key) -> ec2.Vpc:
        """Create VPC 10.2.0.0/16 (2 AZs, public + private subnets) with flow logs.

        Layout:
            private subnets — Fargate tasks, Aurora, Valkey, Lambda provisioner
            public subnets  — ALB only; NAT gateways provide private egress

        Flow logs:
            ALL traffic logged to CloudWatch Logs, encrypted with the
            platform KMS key.  Retention: 1 year (satisfies HIPAA log
            retention guidance for infrastructure logs).

        Args:
            kms_key: Platform CMK used to encrypt the flow log group.

        Returns:
            The created VPC.
        """
        vpc = ec2.Vpc(
            self.scope,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr(VPC_CIDR),
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                ),
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    map_public_ip_on_launch=False,
                ),
            ],
        )

        # ---- Flow logs -------------------------------------------------------
        flow_log_group = logs.LogGroup(
            self.scope,
            "VpcFlowLogGroup",
            encryption_key=kms_key,
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.DESTROY,
        )

        flow_log_role = iam.Role(
            self.scope,
            "VpcFlowLogRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
        )

        vpc.add_flow_log(
            "FlowLog",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                flow_log_group, flow_log_role
            ),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )

        # ---- Nag suppressions ------------------------------------------------
        NagSuppressions.add_resource_suppressions(
            vpc,
            [
                {
                    "id": "HIPAA.Security-VPCDefaultSecurityGroupClosed",
                    "reason": (
                        "Default SG is not used — all resources are assigned "
                        "explicit, scoped security groups."
                    ),
                },
            ],
        )

        for subnet in vpc.public_subnets:
            NagSuppressions.add_resource_suppressions(
                subnet,
                [
                    {
                        "id": "HIPAA.Security-VPCNoUnrestrictedRouteToIGW",
                        "reason": (
                            "Public subnets need an IGW route for the shared "
                            "internet-facing ALB.  Inbound traffic is restricted "
                            "to HTTPS (443) only by the ALB security group."
                        ),
                    }
                ],
                apply_to_children=True,
            )

        NagSuppressions.add_resource_suppressions(
            flow_log_role,
            [
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "CDK generates an inline DefaultPolicy on the flow-log "
                        "IAM role for CloudWatch Logs permissions.  This is "
                        "CDK-managed and follows least privilege."
                    ),
                },
            ],
            apply_to_children=True,
        )

        # ---- SSM exports -----------------------------------------------------
        ssm.StringParameter(
            self.scope,
            "VpcIdParam",
            parameter_name=SSM_VPC_ID,
            string_value=vpc.vpc_id,
            description="Shared VPC ID",
        )
        # Private subnet IDs joined as a comma-separated string.
        # Fn.join() is used because subnet_id values are CDK Tokens;
        # Python str.join() does not produce a valid CloudFormation expression.
        ssm.StringParameter(
            self.scope,
            "PrivateSubnetsParam",
            parameter_name=SSM_PRIVATE_SUBNETS,
            string_value=Fn.join(",", [s.subnet_id for s in vpc.private_subnets]),
            description="Comma-separated private subnet IDs (2 AZs)",
        )

        self.vpc = vpc
        return vpc

    # ── Security groups ─────────────────────────────────────────────────────

    def create_security_groups(
        self,
        vpc: ec2.Vpc,
    ) -> tuple[ec2.SecurityGroup, ec2.SecurityGroup, ec2.SecurityGroup, ec2.SecurityGroup]:
        """Create all platform-wide security groups.

        Returns a tuple of four security groups in this order:
            (alb_sg, aurora_sg, valkey_sg, container_sg)

        alb_sg:
            Internet-facing ALB.  HTTPS (443) ingress from 0.0.0.0/0 and
            ::/0.  ``allow_all_outbound=True`` is intentional — it avoids
            a CDK cross-stack circular dependency when TenantStack adds its
            per-tenant task SG.  The ALB SG is in SharedInfraStack; the
            task SG is in TenantStack.  If we tried to add an egress rule
            from alb_sg to task_sg, CDK would create a cross-stack
            dependency that CloudFormation refuses to delete in the right
            order (confirmed in Sprint 3).

        aurora_sg:
            Aurora Serverless v2 cluster.  No ingress rules at stack
            creation time.  TenantStack adds:
                ``aurora_sg.connections.allow_from(task_sg, Port.tcp(3306))``

        valkey_sg:
            Valkey (ElastiCache Serverless).  Same pattern as aurora_sg.
            TenantStack adds ingress on port 6379.

        container_sg:
            Baseline ECS task security group shared across tenants.
            Accepts HTTPS (443) from alb_sg.  Each TenantStack
            may create an additional per-tenant SG if finer isolation
            is needed.
        """
        # ---- ALB SG ---------------------------------------------------------
        alb_sg = ec2.SecurityGroup(
            self.scope,
            "AlbSg",
            vpc=vpc,
            description="Shared ALB - HTTPS inbound from internet",
            # allow_all_outbound=True prevents cross-stack circular SG deps
            # (confirmed pattern from Sprint 3 — see Notes in SPRINTS.md)
            allow_all_outbound=True,
        )
        alb_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "HTTPS from internet IPv4",
        )
        alb_sg.add_ingress_rule(
            ec2.Peer.any_ipv6(),
            ec2.Port.tcp(443),
            "HTTPS from internet IPv6",
        )

        NagSuppressions.add_resource_suppressions(
            alb_sg,
            [
                {
                    "id": "AwsSolutions-EC23",
                    "reason": (
                        "Shared ALB is intentionally internet-facing on port 443 "
                        "to serve all tenants via host-based routing."
                    ),
                },
                {
                    "id": "HIPAA.Security-EC2SecurityGroupIngressOpenToWorld",
                    "reason": (
                        "Internet-facing ALB must accept HTTPS (443) from the public "
                        "internet.  All other ports are blocked."
                    ),
                },
            ],
        )

        # ---- Aurora SG ------------------------------------------------------
        # No ingress at creation — TenantStack adds port 3306 from its task SG.
        aurora_sg = ec2.SecurityGroup(
            self.scope,
            "AuroraSg",
            vpc=vpc,
            description="Aurora cluster - MySQL ingress from ECS task SGs only",
            allow_all_outbound=False,
        )

        # ---- Valkey SG ------------------------------------------------------
        # No ingress at creation — TenantStack adds port 6379 from its task SG.
        valkey_sg = ec2.SecurityGroup(
            self.scope,
            "ValkeySg",
            vpc=vpc,
            description="Valkey cluster - Redis ingress from ECS task SGs only",
            allow_all_outbound=False,
        )
        # RETAIN matches the Valkey cache policy: ValkeyCluster is RETAIN-ed via
        # cfn_options.deletion_policy=RETAIN, so the SG it uses must also be
        # RETAIN-ed to prevent ROLLBACK_FAILED when CloudFormation tries to delete
        # the SG while the serverless cache still holds a reference to it.
        valkey_sg.apply_removal_policy(RemovalPolicy.RETAIN)

        # ---- Container SG ---------------------------------------------------
        # Baseline task SG.  Accepts HTTPS from the ALB; tenants inherit this
        # or create their own additional SG in TenantStack.
        container_sg = ec2.SecurityGroup(
            self.scope,
            "ContainerSg",
            vpc=vpc,
            description="ECS container baseline SG - HTTPS from ALB",
            allow_all_outbound=True,  # tasks need ECR, Secrets Manager, internet
        )
        container_sg.add_ingress_rule(
            alb_sg,
            ec2.Port.tcp(CONTAINER_PORT),
            "HTTPS from shared ALB to OpenEMR containers",
        )

        # ---- SSM exports -----------------------------------------------------
        ssm.StringParameter(
            self.scope,
            "AlbSgIdParam",
            parameter_name=SSM_ALB_SG_ID,
            string_value=alb_sg.security_group_id,
            description="Shared ALB security group ID",
        )
        ssm.StringParameter(
            self.scope,
            "AuroraSgIdParam",
            parameter_name=SSM_AURORA_SG_ID,
            string_value=aurora_sg.security_group_id,
            description="Aurora cluster security group ID",
        )
        ssm.StringParameter(
            self.scope,
            "ValkeySgIdParam",
            parameter_name=SSM_VALKEY_SG_ID,
            string_value=valkey_sg.security_group_id,
            description="Valkey cluster security group ID",
        )
        ssm.StringParameter(
            self.scope,
            "ContainerSgIdParam",
            parameter_name=SSM_CONTAINER_SG_ID,
            string_value=container_sg.security_group_id,
            description="ECS container task SG ID - used by TenantStack for EFS NFS access rules",
        )

        self.alb_sg    = alb_sg
        self.aurora_sg = aurora_sg
        self.valkey_sg = valkey_sg
        self.ecs_sg    = container_sg

        return alb_sg, aurora_sg, valkey_sg, container_sg

    # ── ALB ────────────────────────────────────────────────────────────────────

    def create_alb(
        self,
        vpc: ec2.Vpc,
        alb_sg: ec2.SecurityGroup,
    ) -> elb.ApplicationLoadBalancer:
        """Create internet-facing ALB with S3 access logs and deletion protection.

        Access log bucket:
            ALB requires an S3 bucket with an ALB-managed bucket policy.
            ALB does NOT support KMS-CMK encrypted buckets for access logs
            (AWS constraint) — SSE-S3 (AES-256) is used instead.  Nag
            findings about KMS default encryption are suppressed with this
            justification.

        Deletion protection:
            Enabled (HIPAA).  To destroy the stack during sprint testing,
            disable via the AWS Console or CLI before running cdk destroy:
                aws elbv2 modify-load-balancer-attributes \\
                    --load-balancer-arn <arn> \\
                    --attributes Key=deletion_protection.enabled,Value=false

        Returns:
            The created ApplicationLoadBalancer.
        """
        # ---- S3 access-log bucket (SSE-S3 only — ALB cannot write to KMS buckets)
        log_bucket = s3.Bucket(
            self.scope,
            "AlbLogBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=False,
            encryption=s3.BucketEncryption.S3_MANAGED,
        )

        NagSuppressions.add_resource_suppressions(
            log_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "ALB access-log bucket — self-referential server access logging is not required.",
                },
                {
                    "id": "HIPAA.Security-S3BucketLoggingEnabled",
                    "reason": "ALB access-log bucket — self-referential access logging not needed.",
                },
                {
                    "id": "HIPAA.Security-S3BucketReplicationEnabled",
                    "reason": "ALB access-log bucket — cross-region replication not required for sprint.",
                },
                {
                    "id": "HIPAA.Security-S3BucketVersioningEnabled",
                    "reason": "ALB access-log bucket — versioning not required for access logs.",
                },
                {
                    "id": "HIPAA.Security-S3DefaultEncryptionKMS",
                    "reason": (
                        "ALB access logs cannot be written to KMS-encrypted S3 buckets — "
                        "this is an AWS ALB service constraint.  SSE-S3 is used instead."
                    ),
                },
            ],
        )

        # ---- Application Load Balancer ----------------------------------------
        alb = elb.ApplicationLoadBalancer(
            self.scope,
            "SharedAlb",
            vpc=vpc,
            internet_facing=True,
            security_group=alb_sg,
            drop_invalid_header_fields=True,
            deletion_protection=True,
        )
        alb.log_access_logs(log_bucket, prefix="alb")

        NagSuppressions.add_resource_suppressions(
            alb,
            [
                {
                    "id": "AwsSolutions-ELB2",
                    "reason": "ALB access logs are enabled via log_access_logs().",
                },
            ],
        )

        # ---- SSM exports -----------------------------------------------------
        ssm.StringParameter(
            self.scope,
            "AlbArnParam",
            parameter_name=SSM_ALB_ARN,
            string_value=alb.load_balancer_arn,
            description="Shared ALB ARN",
        )
        ssm.StringParameter(
            self.scope,
            "AlbDnsParam",
            parameter_name=SSM_ALB_DNS,
            string_value=alb.load_balancer_dns_name,
            description="Shared ALB DNS name (for Route53 alias records)",
        )
        ssm.StringParameter(
            self.scope,
            "AlbHostedZoneParam",
            parameter_name=SSM_ALB_HOSTED_ZONE,
            string_value=alb.load_balancer_canonical_hosted_zone_id,
            description="Shared ALB canonical hosted zone ID (for Route53 alias records)",
        )

        self.alb        = alb
        self.log_bucket = log_bucket
        return alb

    def add_https_listener(
        self,
        alb: elb.ApplicationLoadBalancer,
        certificate: acm.ICertificate,
    ) -> elb.ApplicationListener:
        """Attach HTTPS/443 listener to the ALB with a default 404 fixed-response.

        The default action returns HTTP 404 when no tenant listener rule matches
        the request's Host header.  Each TenantStack adds a host-header rule
        that forwards its subdomain to its own target group.

        SSL policy:
            RECOMMENDED_TLS — TLS 1.2+ only; disables older cipher suites.

        open=False:
            SG ingress on port 443 was already added by create_security_groups().
            Setting open=False prevents CDK from auto-adding a duplicate rule.

        Returns:
            The created ApplicationListener.
        """
        listener = alb.add_listener(
            "HttpsListener",
            port=443,
            ssl_policy=elb.SslPolicy.RECOMMENDED_TLS,
            certificates=[certificate],
            default_action=elb.ListenerAction.fixed_response(
                status_code=404,
                content_type="text/plain",
                message_body="No tenant matched this hostname.",
            ),
            open=False,
        )

        ssm.StringParameter(
            self.scope,
            "HttpsListenerArnParam",
            parameter_name=SSM_HTTPS_LISTENER_ARN,
            string_value=listener.listener_arn,
            description="Shared HTTPS listener ARN (TenantStack adds host-header rules here)",
        )

        self.https_listener = listener
        return listener

    # ── WAF ───────────────────────────────────────────────────────────────────

    def create_waf(
        self,
        alb: elb.ApplicationLoadBalancer,
        kms_key: kms.Key,
    ) -> wafv2.CfnWebACL:
        """Create a WAFv2 WebACL with AWS managed rule groups and associate it with the ALB.

        Managed rule groups (REGIONAL scope):
            Priority 10 — AWSManagedRulesCommonRuleSet
                Core OWASP Top 10 protections: XSS, RFI, path traversal.
            Priority 20 — AWSManagedRulesKnownBadInputsRuleSet
                Log4Shell, Spring4Shell, SSRF probes, malformed request patterns.
            Priority 30 — AWSManagedRulesSQLiRuleSet
                SQL injection protection — critical for the Aurora MySQL backend.

        Logging:
            All WAF decisions are logged to a CloudWatch Log Group whose name
            starts with ``aws-waf-logs-`` (AWS requirement for WAF log delivery).
            The log group is KMS-encrypted with the platform CMK.

        Args:
            alb:     The shared ALB to protect.
            kms_key: Platform CMK used to encrypt the WAF log group.

        Returns:
            The created CfnWebACL.
        """
        # ---- WAF log group (name MUST start with 'aws-waf-logs-') ---------------
        region   = Stack.of(self.scope).region
        acct     = Stack.of(self.scope).account
        log_group_name = f"aws-waf-logs-tarevo-{acct}-{region}"

        waf_log_group = logs.LogGroup(
            self.scope,
            "WafLogGroup",
            log_group_name=log_group_name,
            encryption_key=kms_key,
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # ---- WebACL -------------------------------------------------------------
        web_acl = wafv2.CfnWebACL(
            self.scope,
            "WebAcl",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="TarevoWebAcl",
                sampled_requests_enabled=True,
            ),
            rules=[
                _managed_rule("AWSManagedRulesCommonRuleSet",         priority=10),
                _managed_rule("AWSManagedRulesKnownBadInputsRuleSet", priority=20),
                _managed_rule("AWSManagedRulesSQLiRuleSet",           priority=30),
            ],
        )

        # ---- Associate WebACL with the ALB -------------------------------------
        wafv2.CfnWebACLAssociation(
            self.scope,
            "WebAclAssociation",
            resource_arn=alb.load_balancer_arn,
            web_acl_arn=web_acl.attr_arn,
        )

        # ---- Enable WAF logging to CloudWatch -----------------------------------
        wafv2.CfnLoggingConfiguration(
            self.scope,
            "WafLogging",
            log_destination_configs=[waf_log_group.log_group_arn],
            resource_arn=web_acl.attr_arn,
        )

        self.waf_acl = web_acl
        return web_acl


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _managed_rule(name: str, priority: int) -> wafv2.CfnWebACL.RuleProperty:
    """Build a WAFv2 RuleProperty for an AWS managed rule group."""
    return wafv2.CfnWebACL.RuleProperty(
        name=name,
        priority=priority,
        override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
        visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
            cloud_watch_metrics_enabled=True,
            metric_name=name,
            sampled_requests_enabled=True,
        ),
        statement=wafv2.CfnWebACL.StatementProperty(
            managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                name=name,
                vendor_name="AWS",
            )
        ),
    )
