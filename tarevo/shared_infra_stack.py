"""SharedInfraStack — shared infrastructure for all Tarevo tenants.

Sprint 4 production implementation.  All SharedInfraStack components are
complete (Sprints 4.1–11).  TenantStack components follow in Sprints 4.12–16.

Resources created (85 CloudFormation resources, zero nag errors):
  1.  KMS customer-managed key (security — Sprint 4.1)
  2.  ACM wildcard certificate for *.tarevoehr.app (security — Sprint 4.1)
  3.  VPC 10.2.0.0/16, 2 AZs, public + private subnets (network — Sprint 4.2)
  4.  Security groups: ALB, Aurora, Valkey, container (network — Sprint 4.2)
  5.  Internet-facing ALB + WAF (network — Sprint 4.3)
  6.  HTTPS listener, default 404 (network — Sprint 4.3)
  7.  Aurora Serverless v2 cluster (database — Sprint 4.4)
  8.  Valkey (ElastiCache Serverless) cluster (database — Sprint 4.5)
  9.  Tenant registry DynamoDB table (database — Sprint 4.6)
  10. ECS cluster with enhanced container insights (compute — Sprint 4.7)
  11. Tenant DB provisioner Lambda (provisioner — Sprint 4.8)
  12. SSM exports of all 19 shared resource identifiers (inline — Sprints 4.9/4.12)
  13. ECR repository tarevo-openemr (compute — Sprint 4.10)
"""

from typing import Optional

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr as ecr
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
    cluster:  Optional[ecs.Cluster]     = None
    ecr_repo: Optional[ecr.Repository] = None

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

        # === Build sequence — SharedInfraStack (Sprints 4.1–11 COMPLETE) ===
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
        # Sprint 4.3 — ALB + WAF (COMPLETE)
        self.alb            = _network.create_alb(self.vpc, self.alb_sg)
        self.https_listener = _network.add_https_listener(self.alb, self.certificate)
        _network.create_waf(self.alb, self.kms_key)
        #
        # Sprint 4.4 — Aurora Serverless v2 (COMPLETE)
        self.aurora_cluster, self.aurora_admin_secret = _database.create_aurora(
            self.vpc, self.aurora_sg, self.kms_key
        )
        # Sprint 4.5 — Valkey Serverless (COMPLETE)
        self.valkey_cluster = _database.create_valkey(self.vpc, self.valkey_sg, self.kms_key)
        #
        # Sprint 4.6 — DynamoDB tenant registry (COMPLETE)
        self.tenant_table = _database.create_tenant_registry(self.kms_key)
        #
        # Sprint 4.7 — ECS Cluster (COMPLETE)
        self.cluster = _compute.create_cluster(self.vpc, self.kms_key)
        #
        # Sprint 4.8 — Provisioner Lambda (COMPLETE)
        self.provisioner_fn = _provisioner.create_lambda(
            self.vpc, self.aurora_sg, self.aurora_cluster,
            self.aurora_admin_secret, self.kms_key,
        )
        #
        # Sprint 4.10 — ECR repository (COMPLETE)
        self.ecr_repo = _compute.create_ecr_repository()
        #
        # Sprint 4.9 — SSM exports (COMPLETE — inline in each component method)
        # Sprint 4.12 added SSM_CONTAINER_SG_ID (network) — total 19 parameters:
        #   security  : SSM_KMS_KEY_ARN
        #   network   : SSM_VPC_ID, SSM_PRIVATE_SUBNETS, SSM_ALB_SG_ID,
        #               SSM_AURORA_SG_ID, SSM_VALKEY_SG_ID, SSM_CONTAINER_SG_ID,
        #               SSM_ALB_ARN, SSM_ALB_DNS, SSM_ALB_HOSTED_ZONE,
        #               SSM_HTTPS_LISTENER_ARN
        #   database  : SSM_AURORA_ENDPOINT, SSM_AURORA_SECRET_ARN,
        #               SSM_VALKEY_ENDPOINT, SSM_TENANT_TABLE_NAME
        #   compute   : SSM_CLUSTER_ARN, SSM_CLUSTER_NAME, SSM_ECR_REPO_URI
        #   provisioner: SSM_PROVISIONER_FN_ARN
        #
        # Sprint 4.11 — Full synth validation (COMPLETE)
        # cdk synth TarevoSharedInfra: exit 0, zero nag errors, 85 resources.
        # SharedInfraStack is production-ready.  TenantStack work begins at
        # Sprint 4.12.
