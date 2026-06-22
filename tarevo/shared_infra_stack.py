"""SharedInfraStack — shared infrastructure for all Tarevo tenants.

Sprint 4 production skeleton.  The stack shape (class-level type annotations
and build-order comments) is defined here; actual resource creation is
implemented incrementally in the component classes under tarevo/components/.

NO component methods are called until they replace their ``raise
NotImplementedError`` stubs — calling a stub would fail ``cdk synth``.

Resources created (in this order once components are implemented):
  1.  KMS customer-managed key (security)
  2.  ACM wildcard certificate for *.tarevoehr.app (security)
  3.  VPC 10.2.0.0/16, 2 AZs, public + private subnets (network)
  4.  Security groups: ALB, Aurora, Valkey, container (network)
  5.  Internet-facing ALB + WAF (network)
  6.  HTTPS listener, default 404 (network)
  7.  Aurora Serverless v2 cluster (database)
  8.  Valkey (ElastiCache Serverless) cluster (database)
  9.  Tenant registry DynamoDB table (database)
  10. ECS cluster with container insights (compute)
  11. Tenant DB provisioner Lambda + Custom Resource (provisioner)
  12. SSM exports of all shared resource identifiers
"""

from typing import Optional

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticache as elasticache
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_rds as rds
from aws_cdk import aws_route53 as route53
from constructs import Construct

from .components.compute import ComputeComponents
from .components.database import DatabaseComponents
from .components.network import NetworkComponents
from .components.provisioner import ProvisionerComponents
from .components.security import SecurityComponents
from .constants import DOMAIN


class SharedInfraStack(Stack):
    """Shared platform infrastructure consumed by every TenantStack.

    All public attributes are set by component methods.  TenantStack reads
    them via SSM parameters (not direct Python references) so there is no
    CloudFormation cross-stack export dependency.
    """

    # ── Security ──────────────────────────────────────────────────────────────
    kms_key:     Optional[kms.Key]             = None
    certificate: Optional[acm.Certificate]     = None
    zone:        Optional[route53.IHostedZone] = None

    # ── Network ───────────────────────────────────────────────────────────────
    vpc:              Optional[ec2.Vpc]                            = None
    alb_sg:           Optional[ec2.SecurityGroup]                  = None
    aurora_sg:        Optional[ec2.SecurityGroup]                  = None
    valkey_sg:        Optional[ec2.SecurityGroup]                  = None
    container_sg:     Optional[ec2.SecurityGroup]                  = None
    alb:              Optional[elbv2.ApplicationLoadBalancer]       = None
    https_listener:   Optional[elbv2.ApplicationListener]          = None

    # ── Database ──────────────────────────────────────────────────────────────
    aurora_cluster:       Optional[rds.DatabaseCluster]     = None
    aurora_admin_secret:  Optional[object]                  = None   # SecretsManager Secret
    valkey_cluster:       Optional[elasticache.CfnServerlessCache] = None
    tenant_table:         Optional[dynamodb.Table]          = None

    # ── Compute ───────────────────────────────────────────────────────────────
    cluster: Optional[ecs.Cluster] = None

    # ── Provisioner ───────────────────────────────────────────────────────────
    provisioner_fn: Optional[_lambda.Function] = None

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Instantiate component helpers (no AWS resources created yet)
        _security    = SecurityComponents(self)
        _network     = NetworkComponents(self)
        _database    = DatabaseComponents(self)
        _compute     = ComputeComponents(self)
        _provisioner = ProvisionerComponents(self)

        # === Build sequence — uncomment each line as its Sprint 4.x task lands ===
        #
        # Sprint 4.1 — Security (COMPLETE)
        self.zone        = route53.HostedZone.from_lookup(self, "Zone", domain_name=DOMAIN)
        self.kms_key     = _security.create_kms_key()
        self.certificate = _security.create_certificate(self.zone)
        #
        # Sprint 4.2 — Network (COMPLETE)
        self.vpc = _network.create_vpc(self.kms_key)
        (
            self.alb_sg,
            self.aurora_sg,
            self.valkey_sg,
            self.container_sg,
        ) = _network.create_security_groups(self.vpc)
        #
        # Sprint 4.3 — ALB + WAF (next sub-task)
        # self.alb            = _network.create_alb(self.vpc, self.alb_sg)
        # self.https_listener = _network.add_https_listener(self.alb, self.certificate)
        # _network.create_waf(self.alb)
        #
        # Sprint 4.3 — Database
        # self.aurora_cluster, self.aurora_admin_secret = _database.create_aurora(
        #     self.vpc, self.aurora_sg, self.kms_key
        # )
        # self.valkey_cluster = _database.create_valkey(self.vpc, self.valkey_sg, self.kms_key)
        # self.tenant_table   = _database.create_tenant_registry(self.kms_key)
        #
        # Sprint 4.4 — Compute
        # self.cluster = _compute.create_cluster(self.vpc)
        #
        # Sprint 4.7 — Provisioner Lambda
        # self.provisioner_fn = _provisioner.create_lambda(
        #     self.vpc, self.aurora_sg, self.aurora_cluster,
        #     self.aurora_admin_secret, self.kms_key,
        # )
        #
        # Sprint 4.13 — SSM exports (all shared identifiers → SSM for TenantStack imports)
        # _publish_ssm_exports(self)
