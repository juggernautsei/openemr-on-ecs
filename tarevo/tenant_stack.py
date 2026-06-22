"""TenantStack — per-tenant infrastructure for one Tarevo customer.

Sprint 4 production skeleton.  TenantStack is NOT instantiated in app.py;
it is deployed on-demand by ``scripts/provision_tenant.py`` after
SharedInfraStack is live.

All shared resource identifiers are read from SSM at **deploy time** using
``ssm.StringParameter.value_for_string_parameter()`` which returns a CDK
Token (``{{resolve:ssm:...}}``) resolved by CloudFormation during
stack deployment.  This avoids hard cross-stack CloudFormation export
dependencies and the synth-time context lookups of ``value_from_lookup``.

Resources created per tenant:
  1.  EFS pair: sites (patient docs) + ssl (certificates)
  2.  7-year AWS Backup plan for EFS volumes (HIPAA retention)
  3.  Fargate service (ARM64/Graviton, OpenEMR container from ECR)
  4.  ALB listener rule: host-header → {tenant_id}.tarevoehr.app
  5.  Route53 A alias → shared ALB
  6.  DB provisioner Custom Resource (invokes SharedInfra Lambda)

Usage (scripts/provision_tenant.py):
    shared = SharedInfraStack.from_ssm(app, env=env)   # lightweight import
    TenantStack(app, f"TarevoTenant-{tenant_id}",
                tenant_id=tenant_id,
                listener_priority=listener_priority,
                env=env)
"""

from aws_cdk import Stack
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
        # These are CDK Tokens: '{{resolve:ssm:/tarevo/shared/...}}'.  They are
        # NOT available at synth time, only when CloudFormation executes.
        #
        # Usage pattern:
        #   _vpc_id             = ssm.StringParameter.value_for_string_parameter(self, "VpcId", SSM_VPC_ID)
        #   _cluster_arn        = ssm.StringParameter.value_for_string_parameter(self, "ClusterArn", SSM_CLUSTER_ARN)
        #   _cluster_name       = ssm.StringParameter.value_for_string_parameter(self, "ClusterName", SSM_CLUSTER_NAME)
        #   _alb_arn            = ssm.StringParameter.value_for_string_parameter(self, "AlbArn", SSM_ALB_ARN)
        #   _alb_hz_id          = ssm.StringParameter.value_for_string_parameter(self, "AlbHzId", SSM_ALB_HOSTED_ZONE)
        #   _alb_sg_id          = ssm.StringParameter.value_for_string_parameter(self, "AlbSgId", SSM_ALB_SG_ID)
        #   _https_listener_arn = ssm.StringParameter.value_for_string_parameter(self, "ListenerArn", SSM_HTTPS_LISTENER_ARN)
        #   _aurora_endpoint    = ssm.StringParameter.value_for_string_parameter(self, "AuroraEndpoint", SSM_AURORA_ENDPOINT)
        #   _aurora_secret_arn  = ssm.StringParameter.value_for_string_parameter(self, "AuroraSecretArn", SSM_AURORA_SECRET_ARN)
        #   _aurora_sg_id       = ssm.StringParameter.value_for_string_parameter(self, "AuroraSgId", SSM_AURORA_SG_ID)
        #   _valkey_endpoint    = ssm.StringParameter.value_for_string_parameter(self, "ValkeyEndpoint", SSM_VALKEY_ENDPOINT)
        #   _kms_key_arn        = ssm.StringParameter.value_for_string_parameter(self, "KmsKeyArn", SSM_KMS_KEY_ARN)
        #   _provisioner_fn_arn = ssm.StringParameter.value_for_string_parameter(self, "ProvisionerFnArn", SSM_PROVISIONER_FN_ARN)
        #
        # To reconstruct CDK objects from the Token strings:
        #   vpc = ec2.Vpc.from_vpc_attributes(self, "Vpc", vpc_id=_vpc_id,
        #             availability_zones=Stack.of(self).availability_zones)
        #   cluster = ecs.Cluster.from_cluster_attributes(self, "Cluster",
        #             cluster_arn=_cluster_arn, cluster_name=_cluster_name,
        #             security_groups=[])
        #   listener = elbv2.ApplicationListener.from_application_listener_attributes(
        #             self, "Listener",
        #             listener_arn=_https_listener_arn,
        #             security_group=ec2.SecurityGroup.from_security_group_id(
        #                 self, "AlbSg", _alb_sg_id))
        #   alb = elbv2.ApplicationLoadBalancer.from_application_load_balancer_attributes(
        #             self, "Alb",
        #             load_balancer_arn=_alb_arn,
        #             security_group_id=_alb_sg_id,
        #             load_balancer_dns_name="placeholder",
        #             load_balancer_canonical_hosted_zone_id=_alb_hz_id)
        #
        # === Build sequence (Sprint 4.8–12) ===
        # _resources = TenantResourcesComponents(self, tenant_id)
        #
        # sites_fs, ssl_fs = _resources.create_efs(vpc, kms_key, tenant_id)
        # _resources.create_backup_plan(sites_fs, ssl_fs, tenant_id)
        # service, tg = _resources.create_fargate_service(
        #     cluster, task_role, exec_role, tenant_id,
        #     _aurora_secret_arn, _valkey_endpoint,
        #     sites_fs, ssl_fs, container_sg,
        # )
        # _resources.add_listener_rule(listener, tg, tenant_id, listener_priority)
        # _resources.create_dns_record(zone, alb, tenant_id)
        #
        # Suppress unused variable warning during skeleton phase.
        _ = ssm  # imported for future use above
