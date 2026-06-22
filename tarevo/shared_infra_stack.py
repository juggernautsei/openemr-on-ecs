"""SharedInfraStack — shared infrastructure for all Tarevo tenants.

Sprint 3 PoC: proves that a single ALB can route to multiple tenants via
host-based listener rules using L2 CDK constructs (no L3 patterns).

Creates:
  - VPC (2 AZs, public + private subnets)
  - ALB security group allowing HTTPS from 0.0.0.0/0
  - Internet-facing Application Load Balancer
  - ACM wildcard certificate for *.tarevoehr.app (DNS validated via Route53)
  - HTTPS listener on port 443 with a default 404 fixed-response action
  - ECS cluster with container insights enabled
"""

from aws_cdk import CfnOutput, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_s3 as s3
from cdk_nag import NagSuppressions
from constructs import Construct

DOMAIN = "tarevoehr.app"


class SharedInfraStack(Stack):
    """Provision shared network + load-balancing infrastructure for Tarevo tenants."""

    # Public attributes consumed by TenantStack instances
    vpc: ec2.Vpc
    alb: elb.ApplicationLoadBalancer
    alb_sg: ec2.SecurityGroup
    https_listener: elb.ApplicationListener
    cluster: ecs.Cluster
    zone: route53.IHostedZone

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── VPC ──────────────────────────────────────────────────────────────
        self.vpc = ec2.Vpc(
            self,
            "PocVpc",
            ip_addresses=ec2.IpAddresses.cidr("10.1.0.0/16"),
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

        # VPC Flow Logs ── write to CloudWatch
        flow_log_role = iam.Role(
            self,
            "FlowLogRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
        )
        flow_log_group = logs.LogGroup(
            self,
            "FlowLogGroup",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )
        NagSuppressions.add_resource_suppressions(
            flow_log_group,
            [
                {
                    "id": "HIPAA.Security-CloudWatchLogGroupEncrypted",
                    "reason": "PoC throwaway VPC flow log group — KMS encryption not required for this non-PHI diagnostic log.",
                }
            ],
        )
        ec2.CfnFlowLog(
            self,
            "VpcFlowLog",
            resource_id=self.vpc.vpc_id,
            resource_type="VPC",
            traffic_type="ALL",
            deliver_logs_permission_arn=flow_log_role.role_arn,
            log_destination_type="cloud-watch-logs",
            log_group_name=flow_log_group.log_group_name,
        )

        # cdk-nag: default SG is not used; suppress false-positive
        NagSuppressions.add_resource_suppressions(
            self.vpc,
            [
                {
                    "id": "HIPAA.Security-VPCDefaultSecurityGroupClosed",
                    "reason": (
                        "Default SG is unused — all resources use explicitly "
                        "scoped security groups."
                    ),
                }
            ],
        )
        for subnet in self.vpc.public_subnets:
            NagSuppressions.add_resource_suppressions(
                subnet,
                [
                    {
                        "id": "HIPAA.Security-VPCNoUnrestrictedRouteToIGW",
                        "reason": (
                            "Public subnets need an IGW route for the shared ALB. "
                            "Inbound is restricted to HTTPS (443) only by ALB SG."
                        ),
                    }
                ],
                apply_to_children=True,
            )

        # ── ALB security group ────────────────────────────────────────────────
        # allow_all_outbound=True so the ALB can forward to per-tenant task SGs
        # in different stacks without creating cross-stack circular dependencies.
        # Ingress is still restricted to HTTPS (port 443) only.
        self.alb_sg = ec2.SecurityGroup(
            self,
            "AlbSg",
            vpc=self.vpc,
            description="Shared ALB - HTTPS inbound from internet",
            allow_all_outbound=True,
        )
        self.alb_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "HTTPS from internet (IPv4)")
        self.alb_sg.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(443), "HTTPS from internet (IPv6)")

        NagSuppressions.add_resource_suppressions(
            self.alb_sg,
            [
                {
                    "id": "AwsSolutions-EC23",
                    "reason": (
                        "PoC shared ALB is intentionally internet-facing on port 443 "
                        "to serve multiple tenants via host-based routing."
                    ),
                }
            ],
        )

        # ── ALB access-log bucket ─────────────────────────────────────────────
        log_bucket = s3.Bucket(
            self,
            "AlbLogBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=False,
        )
        NagSuppressions.add_resource_suppressions(
            log_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "ALB access-log bucket — server-access logging on the log bucket itself is not required.",
                },
                {
                    "id": "HIPAA.Security-S3BucketLoggingEnabled",
                    "reason": "ALB access-log bucket — self-referential logging not needed.",
                },
                {
                    "id": "HIPAA.Security-S3BucketReplicationEnabled",
                    "reason": "PoC throwaway bucket — cross-region replication not required.",
                },
                {
                    "id": "HIPAA.Security-S3BucketVersioningEnabled",
                    "reason": "PoC ALB log bucket — versioning not required for access logs.",
                },
                {
                    "id": "HIPAA.Security-S3DefaultEncryptionKMS",
                    "reason": "PoC ALB log bucket — KMS default encryption not required for throwaway access logs.",
                },
            ],
        )

        # ── Application Load Balancer ─────────────────────────────────────────
        self.alb = elb.ApplicationLoadBalancer(
            self,
            "SharedAlb",
            vpc=self.vpc,
            internet_facing=True,
            security_group=self.alb_sg,
            drop_invalid_header_fields=True,
            # deletion_protection=False for easy PoC destroy
        )
        self.alb.log_access_logs(log_bucket, prefix="alb-access-logs")

        NagSuppressions.add_resource_suppressions(
            self.alb,
            [
                {
                    "id": "AwsSolutions-ELB2",
                    "reason": "ALB access logs are enabled via log_access_logs().",
                },
                {
                    "id": "HIPAA.Security-ELBDeletionProtectionEnabled",
                    "reason": "PoC throwaway ALB — deletion protection intentionally disabled for easy sprint teardown.",
                },
            ],
        )

        # ── Wildcard ACM certificate for *.tarevoehr.app ──────────────────────
        self.zone = route53.HostedZone.from_lookup(
            self,
            "TarevoZone",
            domain_name=DOMAIN,
        )

        self.certificate = acm.Certificate(
            self,
            "WildcardCert",
            domain_name=f"*.{DOMAIN}",
            validation=acm.CertificateValidation.from_dns(self.zone),
        )

        # ── HTTPS listener — default action: 404 ──────────────────────────────
        self.https_listener = self.alb.add_listener(
            "HttpsListener",
            port=443,
            ssl_policy=elb.SslPolicy.RECOMMENDED_TLS,
            certificates=[self.certificate],
            default_action=elb.ListenerAction.fixed_response(
                404,
                content_type="text/plain",
                message_body="No tenant matched this hostname.",
            ),
            open=False,  # SG ingress already configured above
        )

        # ── ECS Cluster ───────────────────────────────────────────────────────
        self.cluster = ecs.Cluster(
            self,
            "SharedCluster",
            vpc=self.vpc,
            container_insights_v2=ecs.ContainerInsights.ENHANCED,
            enable_fargate_capacity_providers=True,
        )

        # ── CloudFormation outputs ────────────────────────────────────────────
        CfnOutput(self, "AlbDnsName", value=self.alb.load_balancer_dns_name)
        CfnOutput(self, "ClusterName", value=self.cluster.cluster_name)
        CfnOutput(self, "CertArn", value=self.certificate.certificate_arn)
