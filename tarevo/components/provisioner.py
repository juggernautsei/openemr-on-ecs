"""Provisioner component — Lambda + Custom Resource for per-tenant DB lifecycle.

The Lambda is deployed once in SharedInfraStack and its ARN is exported via SSM.
Each TenantStack invokes it as a CloudFormation Custom Resource, passing the
tenant_id.  It runs inside the VPC to reach the Aurora private endpoint.

On CREATE:
    1. Fetch admin credentials from the Aurora admin Secrets Manager secret.
    2. Connect to Aurora as admin via pymysql.
    3. CREATE DATABASE IF NOT EXISTS `{tenant_id}_db`.
    4. CREATE USER IF NOT EXISTS `{tenant_id}`@`%` with a generated 32-char password.
    5. GRANT ALL PRIVILEGES ON `{tenant_id}_db`.* TO `{tenant_id}`@`%`.
    6. Store per-tenant credentials in Secrets Manager as JSON:
           /tarevo/tenants/{tenant_id}/db-credentials

On DELETE:
    1-2.  Same admin connect.
    3. DROP DATABASE IF EXISTS `{tenant_id}_db`.
    4. DROP USER IF EXISTS `{tenant_id}`@`%`.
    5. Delete the tenant’s Secrets Manager secret.

On UPDATE:
    No-op — credential rotation is handled separately.
"""

from typing import Optional

from aws_cdk import ArnFormat, BundlingOptions, Duration, Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_rds as rds
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm
from cdk_nag import NagSuppressions
from constructs import Construct

from ..constants import LAMBDA_PYTHON_RUNTIME, MYSQL_PORT, SSM_PROVISIONER_FN_ARN


class ProvisionerComponents:
    """Deploys the tenant-DB provisioner Lambda to SharedInfraStack.

    Build order (called from SharedInfraStack.__init__):
      1. create_lambda(vpc, aurora_sg, aurora_cluster, aurora_admin_secret, kms_key)
    """

    def __init__(self, scope: Construct) -> None:
        self.scope = scope

        # Set by create_lambda()
        self.function: Optional[_lambda.Function] = None

    def create_lambda(
        self,
        vpc: ec2.Vpc,
        aurora_sg: ec2.SecurityGroup,
        aurora_cluster: rds.DatabaseCluster,
        aurora_admin_secret: secretsmanager.ISecret,
        kms_key: kms.Key,
    ) -> _lambda.Function:
        """Deploy the tenant_db_provisioner Lambda in the shared VPC.

        Network
        -------
        A dedicated provisioner security group is created with:
          - Egress TCP 3306 to aurora_sg  (Aurora writer endpoint)
          - Egress TCP 443 to 0.0.0.0/0   (AWS API calls via NAT gateway)
        aurora_sg receives a matching ingress rule from provisioner_sg on 3306.

        IAM grants
        ----------
        aurora_admin_secret.grant_read  — fetch admin MySQL credentials
        kms_key.grant_encrypt_decrypt   — encrypt per-tenant Secrets Manager secrets
        Inline policy for secretsmanager Create/Delete/Tag/Describe scoped to
        /tarevo/tenants/* paths.

        Bundling
        --------
        Python deps (PyMySQL, cfnresponse) are pip-installed into /asset-output
        at synth time using the standard Lambda bundling Docker image.  The
        source is then overlaid so the handler module is importable at runtime.

        Returns:
            The created Lambda Function.
        """
        # ---- Provisioner security group --------------------------------------
        # No ingress — Lambda connects outbound only.
        provisioner_sg = ec2.SecurityGroup(
            self.scope,
            "ProvisionerSg",
            vpc=vpc,
            description="Provisioner Lambda - outbound to Aurora and AWS APIs",
            allow_all_outbound=False,
        )
        # MySQL to Aurora cluster
        provisioner_sg.add_egress_rule(
            ec2.Peer.security_group_id(aurora_sg.security_group_id),
            ec2.Port.tcp(MYSQL_PORT),
            "MySQL to Aurora writer endpoint",
        )
        # HTTPS to AWS APIs (Secrets Manager, CloudWatch) via NAT gateway
        provisioner_sg.add_egress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "HTTPS to AWS APIs via NAT gateway",
        )

        # Allow Aurora to accept inbound from the provisioner
        aurora_sg.add_ingress_rule(
            ec2.Peer.security_group_id(provisioner_sg.security_group_id),
            ec2.Port.tcp(MYSQL_PORT),
            "Provisioner Lambda MySQL access",
        )

        # ---- Lambda function -------------------------------------------------
        fn = _lambda.Function(
            self.scope,
            "ProvisionerFn",
            function_name="tarevo-tenant-db-provisioner",
            description=(
                "CloudFormation Custom Resource: provisions/deprovisions "
                "per-tenant Aurora database and Secrets Manager credentials."
            ),
            runtime=LAMBDA_PYTHON_RUNTIME,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                "tarevo/lambda/tenant_db_provisioner",
                bundling=BundlingOptions(
                    image=LAMBDA_PYTHON_RUNTIME.bundling_image,
                    command=[
                        "bash", "-c",
                        # 1. Install deps into /asset-output so they are importable
                        # 2. Copy source on top (cp -au: archive, update-only skips
                        #    overwriting newer files that pip may have placed there)
                        "pip install --no-cache-dir -r requirements.txt -t /asset-output "
                        "&& cp -au . /asset-output",
                    ],
                ),
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[provisioner_sg],
            environment={
                "AURORA_HOST":         aurora_cluster.cluster_endpoint.hostname,
                "AURORA_PORT":         str(MYSQL_PORT),
                "AURORA_ADMIN_SECRET": aurora_admin_secret.secret_arn,
                # KMS key ARN is passed for use when encrypting tenant secrets.
                # The Lambda will pass it to Secrets Manager in a follow-up sprint.
                "KMS_KEY_ARN":         kms_key.key_arn,
            },
            timeout=Duration.minutes(5),
            # Lambda max is 15 min; 5 min gives generous headroom for DB + SM
            # operations while keeping CloudFormation wait times reasonable.
            reserved_concurrent_executions=5,
            # 5 concurrent provisioner runs is more than enough in practice.
            # This satisfies HIPAA.Security-LambdaConcurrency and prevents
            # runaway CloudFormation recursion from consuming Lambda quota.
        )

        # ---- IAM grants ------------------------------------------------------
        # 1. Read the Aurora admin credentials secret.
        aurora_admin_secret.grant_read(fn)

        # 2. Encrypt / decrypt with the platform KMS key (for tenant secrets).
        kms_key.grant_encrypt_decrypt(fn)

        # 3. Create, delete, and tag per-tenant Secrets Manager secrets.
        #    Scoped to /tarevo/tenants/* — matches the 6-char suffix AWS appends.
        tenant_secret_arn = Stack.of(self.scope).format_arn(
            service="secretsmanager",
            resource="secret",
            resource_name="/tarevo/tenants/*",
            arn_format=ArnFormat.COLON_RESOURCE_NAME,
        )
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ManageTenantSecrets",
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:CreateSecret",
                    "secretsmanager:DeleteSecret",
                    "secretsmanager:TagResource",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",   # read-back after create
                ],
                resources=[tenant_secret_arn],
            )
        )

        # ---- SSM export ------------------------------------------------------
        ssm.StringParameter(
            self.scope,
            "ProvisionerFnArnParam",
            parameter_name=SSM_PROVISIONER_FN_ARN,
            string_value=fn.function_arn,
            description="Tenant DB provisioner Lambda ARN (used by TenantStack CustomResource)",
        )

        # ---- Nag suppressions ------------------------------------------------
        NagSuppressions.add_resource_suppressions(
            fn,
            [
                {
                    "id": "AwsSolutions-L1",
                    "reason": (
                        "Python 3.12 is pinned intentionally.  Upgrade in-step "
                        "with OpenEMR / PyMySQL compatibility testing rather than "
                        "on AWS's release cadence."
                    ),
                },
                {
                    "id": "HIPAA.Security-LambdaInsightLayer",
                    "reason": (
                        "Lambda Insights is not warranted for a short-lived "
                        "provisioner function that runs once per tenant.  Standard "
                        "CloudWatch metrics (duration, errors, throttles) are "
                        "sufficient for operational monitoring."
                    ),
                },
                {
                    "id": "HIPAA.Security-LambdaDLQ",
                    "reason": (
                        "CloudFormation invokes this Custom Resource Lambda "
                        "synchronously.  Dead-letter queues only apply to async "
                        "Lambda invocations; this function is never invoked "
                        "asynchronously, so a DLQ would never receive messages. "
                        "Failures are handled by CloudFormation’s own retry and "
                        "rollback mechanisms."
                    ),
                },
            ],
        )

        # ---- IAM role nag suppressions  ------------------------------------
        # The Lambda execution role receives:
        #   - AWSLambdaBasicExecutionRole (CDK default for all Lambda)
        #   - An inline DefaultPolicy with four sets of statements:
        #       grant_read(aurora_admin_secret)
        #       grant_encrypt_decrypt(kms_key)
        #       add_to_role_policy(ManageTenantSecrets)
        #
        # CDK nag checks IAM4 on the ServiceRole and IAM5/IAMNoInlinePolicy
        # on the ServiceRole/DefaultPolicy/Resource.  Because cdk-nag's
        # apply_to_children propagation doesn’t always reach
        # DefaultPolicy/Resource, we use path-based suppression for IAM5.
        assert fn.role is not None, "Lambda role must exist after Function construction"
        stack    = Stack.of(self.scope)
        fn_path  = f"/{stack.stack_name}/ProvisionerFn"

        # IAM4 — AWS-managed policies on the ServiceRole
        NagSuppressions.add_resource_suppressions(
            fn.role,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": (
                        "CDK attaches AWSLambdaBasicExecutionRole (CloudWatch Logs) "
                        "automatically to every Lambda function.  This managed "
                        "policy is required and follows AWS least-privilege guidance."
                    ),
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
                    ],
                },
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "Inline DefaultPolicy is CDK-generated from grant_read, "
                        "grant_encrypt_decrypt, and add_to_role_policy calls. "
                        "Content is least-privilege and auditable in the CF template."
                    ),
                },
            ],
            apply_to_children=True,
        )

        # IAM5 — wildcard permissions in the DefaultPolicy.
        # Path-based suppression is used because apply_to_children does not
        # always propagate to ServiceRole/DefaultPolicy/Resource in cdk-nag 2.x.
        NagSuppressions.add_resource_suppressions_by_path(
            stack,
            f"{fn_path}/ServiceRole/DefaultPolicy/Resource",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "(1) /tarevo/tenants/* path wildcard is required because "
                        "Secrets Manager appends a 6-char random suffix to secret "
                        "ARNs at creation time. "
                        "(2) kms:GenerateDataKey* and kms:ReEncrypt* are CDK "
                        "grant_encrypt_decrypt standard actions — not authored manually. "
                        "The construct path scopes this suppression to only the "
                        "provisioner Lambda’s DefaultPolicy."
                    ),
                    # No appliesTo — path specificity is the scope boundary.
                    # cdk-nag suppresses all IAM5 findings at this exact path.
                },
            ],
        )

        self.function = fn
        return fn
