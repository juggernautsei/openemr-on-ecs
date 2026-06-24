"""TenantStack — per-tenant infrastructure for one Tarevo customer.

TenantStack is NOT instantiated in app.py for production;
it is deployed on-demand by ``scripts/provision_tenant.py`` after
SharedInfraStack is live.

A synthetic test instance (``TarevoTenant-synth-test``) is registered in
``app.py`` to validate TenantStack nag rules during ``cdk synth``.
It will be removed after Sprint 4.16.

All shared resource identifiers are read from SSM at **deploy time** using
``ssm.StringParameter.value_for_string_parameter()`` which returns a CDK
Token (``{{resolve:ssm:...}}``) resolved by CloudFormation during
stack deployment.  This avoids hard cross-stack CloudFormation export
dependencies and the synth-time context lookups of ``value_from_lookup``.

Private subnet IDs are stored as a CSV string in SSM.  ``Fn.select`` +
``Fn.split`` decompose them into scalar tokens for ``Vpc.from_vpc_attributes``.
The VPC was created with ``max_azs=2`` (Sprint 4.2).

Resources created per tenant:
  1.  EFS pair: sites (patient docs) + ssl (certificates)      — Sprint 4.12
  2.  7-year AWS Backup plan for EFS volumes (HIPAA retention) — Sprint 4.13
  3.  Fargate service (ARM64/Graviton, OpenEMR container from ECR) — Sprint 4.14
  4.  ALB listener rule: host-header → {tenant_id}.tarevoehr.app  — Sprint 4.15
  5.  Route53 A alias → shared ALB                              — Sprint 4.15
  6.  DB provisioner Custom Resource (invokes SharedInfra Lambda) — Sprint 4.16

Usage (scripts/provision_tenant.py):
    TenantStack(app, f"TarevoTenant-{tenant_id}",
                tenant_id=tenant_id,
                listener_priority=listener_priority,
                env=env)
"""

from aws_cdk import Fn, Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_kms as kms
from aws_cdk import aws_ssm as ssm
from constructs import Construct

from .components.tenant_resources import TenantResourcesComponents
from .constants import (
    SSM_ALB_ARN,
    SSM_ALB_HOSTED_ZONE,
    SSM_ALB_SG_ID,
    SSM_AURORA_ENDPOINT,
    SSM_AURORA_SECRET_ARN,
    SSM_AURORA_SG_ID,
    SSM_CLUSTER_ARN,
    SSM_CLUSTER_NAME,
    SSM_HTTPS_LISTENER_ARN,
    SSM_KMS_KEY_ARN,
    SSM_PRIVATE_SUBNETS,
    SSM_PROVISIONER_FN_ARN,
    SSM_VALKEY_ENDPOINT,
    SSM_VPC_ID,
)


class TenantStack(Stack):
    """Per-tenant infrastructure for one Tarevo customer.

    Reads all shared resource identifiers from SSM at deploy time so there
    is no CloudFormation cross-stack export dependency on SharedInfraStack.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        tenant_id: str,
        listener_priority: int,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── Import shared resource identifiers from SSM (deploy-time Token resolution)
        #
        # These are CDK Tokens: '{{resolve:ssm:/tarevo/shared/...}}' resolved by
        # CloudFormation at deploy time — NOT available as Python values at synth time.
        _vpc_id          = ssm.StringParameter.value_for_string_parameter(self, SSM_VPC_ID)
        _private_subnets = ssm.StringParameter.value_for_string_parameter(self, SSM_PRIVATE_SUBNETS)
        _kms_key_arn     = ssm.StringParameter.value_for_string_parameter(self, SSM_KMS_KEY_ARN)
        # Remaining SSM imports (activated as each sprint lands):
        #   _cluster_arn        = ssm.StringParameter.value_for_string_parameter(self, SSM_CLUSTER_ARN)
        #   _cluster_name       = ssm.StringParameter.value_for_string_parameter(self, SSM_CLUSTER_NAME)
        #   _alb_arn            = ssm.StringParameter.value_for_string_parameter(self, SSM_ALB_ARN)
        #   _alb_hz_id          = ssm.StringParameter.value_for_string_parameter(self, SSM_ALB_HOSTED_ZONE)
        #   _alb_sg_id          = ssm.StringParameter.value_for_string_parameter(self, SSM_ALB_SG_ID)
        #   _https_listener_arn = ssm.StringParameter.value_for_string_parameter(self, SSM_HTTPS_LISTENER_ARN)
        #   _aurora_endpoint    = ssm.StringParameter.value_for_string_parameter(self, SSM_AURORA_ENDPOINT)
        #   _aurora_secret_arn  = ssm.StringParameter.value_for_string_parameter(self, SSM_AURORA_SECRET_ARN)
        #   _aurora_sg_id       = ssm.StringParameter.value_for_string_parameter(self, SSM_AURORA_SG_ID)
        #   _valkey_endpoint    = ssm.StringParameter.value_for_string_parameter(self, SSM_VALKEY_ENDPOINT)
        #   _provisioner_fn_arn = ssm.StringParameter.value_for_string_parameter(self, SSM_PROVISIONER_FN_ARN)

        # ── Reconstruct shared objects from SSM Tokens ──────────────────────────
        #
        # VPC: from_vpc_attributes uses Fn.select + Fn.split to decompose the
        # CSV private subnet IDs into per-AZ token strings at deploy time.
        # The VPC was created with max_azs=2 (Sprint 4.2).
        _private_azs = self.availability_zones[:2]   # us-east-2 -> ["us-east-2a", "us-east-2b"]
        vpc = ec2.Vpc.from_vpc_attributes(
            self, "SharedVpc",
            vpc_id=_vpc_id,
            availability_zones=_private_azs,
            private_subnet_ids=[
                Fn.select(0, Fn.split(",", _private_subnets)),
                Fn.select(1, Fn.split(",", _private_subnets)),
            ],
        )

        # KMS key: Key.from_key_arn accepts a Token ARN; CDK serialises it as
        # a CloudFormation Fn::Sub/Ref expression in the generated template.
        platform_kms_key = kms.Key.from_key_arn(self, "PlatformKey", _kms_key_arn)

        # ── Build sequence — TenantStack (Sprints 4.12–16) ─────────────────────
        _resources = TenantResourcesComponents(self, tenant_id)

        # Sprint 4.12 — EFS file systems (COMPLETE)
        sites_fs, ssl_fs = _resources.create_efs(vpc, platform_kms_key, tenant_id)

        # Sprint 4.13 — 7-year backup plan (COMPLETE)
        _resources.create_backup_plan(sites_fs, ssl_fs, tenant_id, platform_kms_key)
        #
        # Sprint 4.14 — Fargate service (TODO)
        # service, tg = _resources.create_fargate_service(
        #     cluster, task_role, exec_role, tenant_id,
        #     _aurora_secret_arn, _valkey_endpoint,
        #     sites_fs, ssl_fs, container_sg,
        # )
        #
        # Sprint 4.15 — Listener rule + DNS (TODO)
        # _resources.add_listener_rule(listener, tg, tenant_id, listener_priority)
        # _resources.create_dns_record(zone, alb, tenant_id)
        #
        # Sprint 4.16 — DB provisioner Custom Resource (TODO)
