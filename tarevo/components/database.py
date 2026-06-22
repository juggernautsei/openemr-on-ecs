"""Database component — shared Aurora Serverless v2, Valkey Serverless, DynamoDB.

All three resources are shared across every tenant.  Per-tenant isolation is
achieved at the database/user/key-prefix level, not the resource level.
"""

from typing import Optional

from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_elasticache as elasticache
from aws_cdk import aws_kms as kms
from aws_cdk import aws_rds as rds
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm
from constructs import Construct

from ..constants import (
    AURORA_ENGINE_VERSION,
    AURORA_MAX_ACU,
    AURORA_MIN_ACU,
    MYSQL_PORT,
    VALKEY_PORT,
)


class DatabaseComponents:
    """Creates the shared Aurora cluster, Valkey cache, and tenant DynamoDB table.

    Build order (called from SharedInfraStack.__init__):
      1. create_aurora(vpc, aurora_sg, kms_key)
      2. create_valkey(vpc, valkey_sg, kms_key)
      3. create_tenant_registry(kms_key)
    """

    def __init__(self, scope: Construct) -> None:
        self.scope = scope

        # Set by create_aurora()
        self.aurora_cluster:      Optional[rds.DatabaseCluster] = None
        self.aurora_admin_secret: Optional[secretsmanager.Secret] = None

        # Set by create_valkey()
        self.valkey_cache: Optional[elasticache.CfnServerlessCache] = None

        # Set by create_tenant_registry()
        self.tenant_table: Optional[dynamodb.Table] = None

    # ── Aurora Serverless v2 ──────────────────────────────────────────────────

    def create_aurora(
        self,
        vpc: ec2.Vpc,
        aurora_sg: ec2.SecurityGroup,
        kms_key: kms.Key,
    ) -> rds.DatabaseCluster:
        """Create the shared Aurora MySQL Serverless v2 cluster.

        Cluster configuration:
            - 1 writer + 1 reader, both Serverless v2
            - Min 0.5 ACU / max 32 ACU (scales to near-zero when idle)
            - Parameter group: require_secure_transport=ON, audit logging
            - deletion_protection=True
            - cloudwatch_logs_exports: audit, error, general, slowquery

        Returns:
            The created DatabaseCluster.

        TODO Sprint 4.4:
            - Create admin secret (KMS encrypted, exclude unsafe punctuation)
            - ParameterGroup with AURORA_ENGINE_VERSION
            - ClusterInstance.serverless_v2('writer') + serverless_v2('reader')
            - ServerlessV2ScalingConfiguration(min_capacity=0.5, max_capacity=32)
            - Store cluster endpoint and admin secret ARN in SSM
            - Suppress AwsSolutions-RDS6 (IAM auth not used), RDS10 (deletion
              protection on), RDS14 (backtrack not supported on SV2 shared cluster)
        """
        raise NotImplementedError("TODO Sprint 4.4: implement create_aurora()")

    # ── Valkey Serverless ─────────────────────────────────────────────────────

    def create_valkey(
        self,
        vpc: ec2.Vpc,
        valkey_sg: ec2.SecurityGroup,
        kms_key: kms.Key,
    ) -> elasticache.CfnServerlessCache:
        """Create a Valkey (Redis-compatible) Serverless cache.

        Shared across all tenants; tenants are isolated by key-prefix convention
        (e.g. "test-a:" prefix on all OpenEMR session/cache keys).

        Returns:
            The created CfnServerlessCache.

        TODO Sprint 4.5:
            - engine="valkey", major_engine_version="8"
            - ServerlessCacheConfiguration (max_data_storage, max_ecpu_per_second)
            - subnet_ids = vpc private subnets
            - security_group_ids = [valkey_sg.security_group_id]
            - kms_key_id = kms_key.key_id
            - Store endpoint in SSM
        """
        raise NotImplementedError("TODO Sprint 4.5: implement create_valkey()")

    # ── DynamoDB tenant registry ──────────────────────────────────────────────

    def create_tenant_registry(self, kms_key: kms.Key) -> dynamodb.Table:
        """Create the DynamoDB table that tracks all provisioned tenants.

        Schema:
            PK  tenant_id   (string)  — e.g. "acme-health"
            Attributes:    subdomain, plan_tier, created_at, status,
                           fargate_service_arn, db_secret_arn

        Returns:
            The created Table.

        TODO Sprint 4.5:
            - billing_mode=PAY_PER_REQUEST
            - encryption=TableEncryption.CUSTOMER_MANAGED (kms_key)
            - point_in_time_recovery=True
            - removal_policy=RETAIN (never accidentally drop tenant records)
            - Store table name in SSM
        """
        raise NotImplementedError("TODO Sprint 4.5: implement create_tenant_registry()")
