"""Network component — VPC, security groups, shared ALB, WAF WebACL.

Owns all L3/L4 network resources that are shared across every tenant.
"""

from typing import Optional

from aws_cdk import RemovalPolicy
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_elasticloadbalancingv2 as elb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_wafv2 as wafv2
from cdk_nag import NagSuppressions
from constructs import Construct

from ..constants import VPC_CIDR


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

    # ── VPC ───────────────────────────────────────────────────────────────────

    def create_vpc(self) -> ec2.Vpc:
        """Create VPC (2 AZs, public + private subnets) with flow logs.

        Returns:
            The created VPC.

        TODO Sprint 4.1:
            - 10.2.0.0/16, max_azs=2
            - PRIVATE_WITH_EGRESS + PUBLIC (map_public_ip_on_launch=False)
            - VPC flow logs → CloudWatch (use KMS key from SecurityComponents)
            - Suppress HIPAA-VPCDefaultSecurityGroupClosed and IGW route warnings
        """
        raise NotImplementedError("TODO Sprint 4.1: implement create_vpc()")

    # ── Security groups ───────────────────────────────────────────────────────

    def create_security_groups(self, vpc: ec2.Vpc) -> None:
        """Create all platform-wide security groups.

        Groups created:
            alb_sg    — internet-facing; HTTPS in, allow_all_outbound=True
            aurora_sg — no ingress at creation; tenants add their task SG
            valkey_sg — no ingress at creation; tenants add their task SG
            ecs_sg    — baseline shared SG; tenants create additional SGs

        TODO Sprint 4.1:
            - alb_sg: allow_all_outbound=True (Sprint 3 pattern)
            - aurora_sg: allow_all_outbound=False; ingress added per-tenant
            - valkey_sg: allow_all_outbound=False; ingress added per-tenant
            - Suppress AwsSolutions-EC23 on alb_sg
        """
        raise NotImplementedError("TODO Sprint 4.1: implement create_security_groups()")

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
