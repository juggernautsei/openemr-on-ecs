"""Tarevo SaaS platform constants.

Single source of truth for values shared across SharedInfraStack,
TenantStack, and all component modules.
"""

from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_rds as rds


# ── Domain ────────────────────────────────────────────────────────────────────
DOMAIN = "tarevoehr.app"

# ── SSM parameter namespace ───────────────────────────────────────────────────
# All shared-infra outputs are published under this prefix so TenantStack
# can import them without hard-coded ARNs.
SSM_PREFIX = "/tarevo/shared"

# Shared resource SSM parameter names
SSM_VPC_ID              = f"{SSM_PREFIX}/vpc-id"
SSM_PRIVATE_SUBNETS     = f"{SSM_PREFIX}/private-subnet-ids"
SSM_ALB_SG_ID           = f"{SSM_PREFIX}/alb-sg-id"
SSM_ALB_ARN             = f"{SSM_PREFIX}/alb-arn"
SSM_ALB_DNS             = f"{SSM_PREFIX}/alb-dns"
SSM_ALB_HOSTED_ZONE     = f"{SSM_PREFIX}/alb-hosted-zone-id"
SSM_HTTPS_LISTENER_ARN  = f"{SSM_PREFIX}/https-listener-arn"
SSM_CLUSTER_ARN         = f"{SSM_PREFIX}/cluster-arn"
SSM_CLUSTER_NAME        = f"{SSM_PREFIX}/cluster-name"
SSM_AURORA_ENDPOINT     = f"{SSM_PREFIX}/aurora-endpoint"
SSM_AURORA_SECRET_ARN   = f"{SSM_PREFIX}/aurora-secret-arn"
SSM_AURORA_SG_ID        = f"{SSM_PREFIX}/aurora-sg-id"
SSM_VALKEY_ENDPOINT     = f"{SSM_PREFIX}/valkey-endpoint"
SSM_VALKEY_SG_ID        = f"{SSM_PREFIX}/valkey-sg-id"
SSM_KMS_KEY_ARN         = f"{SSM_PREFIX}/kms-key-arn"
SSM_PROVISIONER_FN_ARN  = f"{SSM_PREFIX}/tenant-provisioner-fn-arn"
SSM_TENANT_TABLE_NAME   = f"{SSM_PREFIX}/tenant-table-name"

# ── Network ───────────────────────────────────────────────────────────────────
VPC_CIDR = "10.2.0.0/16"

# ── Ports ─────────────────────────────────────────────────────────────────────
CONTAINER_PORT = 443    # HTTPS — OpenEMR container terminates TLS internally
MYSQL_PORT     = 3306
VALKEY_PORT    = 6379
NFS_PORT       = 2049

# ── Aurora Serverless v2 ──────────────────────────────────────────────────────
AURORA_ENGINE_VERSION       = rds.AuroraMysqlEngineVersion.VER_3_12_0
AURORA_MIN_ACU              = 0.5   # Scales to zero when idle
AURORA_MAX_ACU              = 32    # ~2 r6g.large equivalent

# ── ECS / Fargate ─────────────────────────────────────────────────────────────
OPENEMR_VERSION             = "8.1.0"
FARGATE_CPU                 = 2048
FARGATE_MEMORY              = 4096
LAMBDA_PYTHON_RUNTIME       = _lambda.Runtime.PYTHON_3_12

# ── ECR image ─────────────────────────────────────────────────────────────────
# Populated after Sprint 2 ECR push.  Override per-tenant if needed.
ECR_IMAGE_URI = "600430252128.dkr.ecr.us-east-2.amazonaws.com/tarevo-openemr:latest"

# ── Backup retention ──────────────────────────────────────────────────────────
BACKUP_RETENTION_DAYS = 2555   # 7 years (HIPAA requirement)
