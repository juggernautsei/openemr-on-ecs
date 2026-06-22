"""Network component — VPC, security groups, shared ALB, WAF WebACL.

Owns all L3/L4 network resources that are shared across every tenant.
"""

from typing import Optional

from aws_cdk import RemovalPolicy
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_elasticloadbalancingv2 as elb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_wafv2 as wafv2
from cdk_nag import NagSuppressions
from constructs import Construct

from ..constants import CONTAINER_PORT, VPC_CIDR


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

        self.alb_sg    = alb_sg
        self.aurora_sg = aurora_sg
        self.valkey_sg = valkey_sg
        self.ecs_sg    = container_sg

        return alb_sg, aurora_sg, valkey_sg, container_sg

    # ── ALB ───────────────────────────────────────────────────────────────────

    def create_alb(self, vpc: ec2.Vpc, alb_sg: ec2.SecurityGroup) -> elb.ApplicationLoadBalancer:
        """Create internet-facing Application Load Balancer with access logs.

        Returns:
            The created ALB.

        TODO Sprint 4.2:
            - Create SSE-S3 log bucket (ALB does not support KMS-encrypted buckets)
            - drop_invalid_header_fields=True
            - deletion_protection=True (HIPAA)
            - log_access_logs(log_bucket)
            - Suppress ELB2 (logs enabled), S3 encryption/replication for log bucket
        """
        raise NotImplementedError("TODO Sprint 4.2: implement create_alb()")

    def add_https_listener(
        self,
        alb: elb.ApplicationLoadBalancer,
        certificate: "acm.ICertificate",  # noqa: F821 — forward ref
    ) -> elb.ApplicationListener:
        """Attach HTTPS/443 listener with default 404 fixed-response.

        Returns:
            The created listener (stored as self.https_listener).

        TODO Sprint 4.2:
            - ssl_policy=SslPolicy.RECOMMENDED_TLS
            - default_action=ListenerAction.fixed_response(404, ...)
            - open=False (SG ingress already configured)
        """
        raise NotImplementedError("TODO Sprint 4.2: implement add_https_listener()")

    # ── WAF ───────────────────────────────────────────────────────────────────

    def create_waf(self, alb: elb.ApplicationLoadBalancer) -> wafv2.CfnWebACL:
        """Create AWS WAF WebACL and associate it with the shared ALB.

        Managed rule groups applied:
            - AWSManagedRulesCommonRuleSet
            - AWSManagedRulesKnownBadInputsRuleSet
            - AWSManagedRulesSQLiRuleSet

        Returns:
            The created WebACL.

        TODO Sprint 4.3:
            - scope=REGIONAL, default_action=Allow
            - Associate via CfnWebACLAssociation with alb.load_balancer_arn
            - Suppress AwsSolutions-WAF4 (sampled requests enabled for cost)
        """
        raise NotImplementedError("TODO Sprint 4.3: implement create_waf()")
