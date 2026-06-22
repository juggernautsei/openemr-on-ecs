"""Provisioner component — Lambda + Custom Resource for per-tenant DB lifecycle.

The Lambda is deployed once in SharedInfraStack and its ARN is exported via SSM.
Each TenantStack invokes it as a Custom Resource, passing the tenant_id.

On CREATE:
    1. Connects to the shared Aurora cluster using the admin secret.
    2. Creates database ``{tenant_id}_db``.
    3. Creates user ``{tenant_id}`` with a generated password.
    4. GRANTs ALL on the tenant database to the tenant user.
    5. Stores credentials in Secrets Manager (JSON: host, user, password, db).

On DELETE:
    1. Connects to Aurora using the admin secret.
    2. DROPs database ``{tenant_id}_db``.
    3. DROPs user ``{tenant_id}``.
    4. Deletes the Secrets Manager secret for the tenant.

On UPDATE:
    No-op — credential rotation is handled separately.
"""

from typing import Optional

from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_rds as rds
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm
from constructs import Construct

from ..constants import LAMBDA_PYTHON_RUNTIME, SSM_PROVISIONER_FN_ARN


class ProvisionerComponents:
    """Deploys the tenant-DB provisioner Lambda to SharedInfraStack.

    Build order (called from SharedInfraStack.__init__):
      1. create_lambda(vpc, aurora_sg, aurora_cluster, aurora_admin_secret, kms_key)
    """

    def __init__(self, scope: Construct) -> None:
        self.scope = scope

        # Set by create_lambda()
        self.function:   Optional[_lambda.Function] = None

    def create_lambda(
        self,
        vpc: ec2.Vpc,
        aurora_sg: ec2.SecurityGroup,
        aurora_cluster: rds.DatabaseCluster,
        aurora_admin_secret: secretsmanager.Secret,
        kms_key: kms.Key,
    ) -> _lambda.Function:
        """Deploy the tenant_db_provisioner Lambda in the VPC.

        The Lambda must run inside the VPC to reach the Aurora cluster.
        It is granted read access to the Aurora admin secret.

        Returns:
            The created Lambda Function.

        TODO Sprint 4.7:
            - runtime=LAMBDA_PYTHON_RUNTIME, handler="index.handler"
            - code=Code.from_asset("tarevo/lambda/tenant_db_provisioner",
                bundling=BundlingOptions(image=..., command=[pip install -r requirements.txt]))
            - vpc=vpc, vpc_subnets=PRIVATE_WITH_EGRESS
            - security_groups — create dedicated SG; allow MYSQL_PORT to aurora_sg
            - Grant aurora_admin_secret.grant_read(function.role)
            - Grant kms_key.grant_encrypt_decrypt(function.role) for Secrets Manager
            - Grant secretsmanager:CreateSecret, DeleteSecret, TagResource (for per-tenant secrets)
            - Store function.function_arn in SSM under SSM_PROVISIONER_FN_ARN
            - Suppress AwsSolutions-L1 (runtime pinned intentionally),
              HIPAA-LambdaInsightLayer (not needed for short-lived provisioner)
        """
        raise NotImplementedError("TODO Sprint 4.7: implement create_lambda()")
