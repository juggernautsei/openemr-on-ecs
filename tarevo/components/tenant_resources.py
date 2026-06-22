"""Tenant Resources component — all per-tenant infrastructure created by TenantStack.

Each public method is called once per tenant deployment.

Build order (called from TenantStack.__init__):
  1. create_efs(vpc, kms_key, tenant_id)
  2. create_backup_plan(sites_fs, ssl_fs, tenant_id)
  3. create_fargate_service(cluster, task_role, exec_role, tenant_id, aurora_secret_arn,
                           valkey_endpoint, sites_fs, ssl_fs, container_sg)
  4. add_listener_rule(listener, target_group, tenant_id, priority)
  5. create_dns_record(hosted_zone, alb, tenant_id)
"""

from typing import Optional

from aws_cdk import aws_backup as backup
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_efs as efs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_secretsmanager as secretsmanager
from constructs import Construct

from ..constants import (
    BACKUP_RETENTION_DAYS,
    CONTAINER_PORT,
    DOMAIN,
)


class TenantResourcesComponents:
    """Creates all per-tenant resources within a TenantStack.

    All outputs are stored as instance attributes for cross-method access.
    """

    def __init__(self, scope: Construct, tenant_id: str) -> None:
        self.scope = scope
        self.tenant_id = tenant_id

        # Set by create_efs()
        self.sites_fs: Optional[efs.FileSystem] = None
        self.ssl_fs:   Optional[efs.FileSystem] = None

        # Set by create_backup_plan()
        self.backup_plan: Optional[backup.BackupPlan] = None

        # Set by create_fargate_service()
        self.fargate_service:  Optional[ecs.FargateService] = None
        self.target_group:     Optional[elbv2.ApplicationTargetGroup] = None

        # Set by add_listener_rule()
        self.listener_rule: Optional[elbv2.ApplicationListenerRule] = None

        # Set by create_dns_record()
        self.dns_record: Optional[route53.ARecord] = None

    # ------------------------------------------------------------------ #
    # 1. EFS                                                               #
    # ------------------------------------------------------------------ #
    def create_efs(
        self,
        vpc: ec2.Vpc,
        kms_key: kms.Key,
        tenant_id: str,
    ) -> tuple[efs.FileSystem, efs.FileSystem]:
        """Create a pair of encrypted EFS file systems for this tenant.

        File systems:
          - sites_fs: OpenEMR sites directory (patient docs, config)
          - ssl_fs:   SSL certificates directory

        Lifecycle policy: AFTER_7_DAYS -> Infrequent Access tier.
        Removal policy: RETAIN (never delete patient data automatically).

        Returns:
            (sites_fs, ssl_fs)

        TODO Sprint 4.8:
            - encrypted=True, kms_key=kms_key
            - lifecycle_policy=AFTER_7_DAYS
            - removal_policy=RETAIN
            - file_system_name=f"{tenant_id}-sites" / f"{tenant_id}-ssl"
            - Suppress AwsSolutions-EFS1 (backup handled separately via backup plan)
        """
        raise NotImplementedError("TODO Sprint 4.8: implement create_efs()")

    # ------------------------------------------------------------------ #
    # 2. Backup                                                            #
    # ------------------------------------------------------------------ #
    def create_backup_plan(
        self,
        sites_fs: efs.FileSystem,
        ssl_fs: efs.FileSystem,
        tenant_id: str,
    ) -> backup.BackupPlan:
        """Create a 7-year backup plan for tenant EFS volumes.

        Retention: BACKUP_RETENTION_DAYS (2555 = 7 years).
        Schedule: daily at 03:00 UTC.
        Move to cold storage after 90 days.

        Returns:
            BackupPlan

        TODO Sprint 4.9:
            - BackupPlan.daily35_day_retention() is NOT enough — build custom plan
            - Rule: move_to_cold_storage_after=Duration.days(90),
                    delete_after=Duration.days(BACKUP_RETENTION_DAYS)
            - Add both sites_fs and ssl_fs as resources
        """
        raise NotImplementedError("TODO Sprint 4.9: implement create_backup_plan()")

    # ------------------------------------------------------------------ #
    # 3. Fargate service                                                   #
    # ------------------------------------------------------------------ #
    def create_fargate_service(
        self,
        cluster: ecs.Cluster,
        task_role: iam.Role,
        exec_role: iam.Role,
        tenant_id: str,
        aurora_secret_arn: str,
        valkey_endpoint: str,
        sites_fs: efs.FileSystem,
        ssl_fs: efs.FileSystem,
        container_sg: ec2.SecurityGroup,
    ) -> tuple[ecs.FargateService, elbv2.ApplicationTargetGroup]:
        """Create a Fargate service running OpenEMR for this tenant.

        Architecture: ARM64 (Graviton).
        Image: from ECR (ECR_IMAGE_URI constant).
        TLS terminated in-container on CONTAINER_PORT (443).
        EFS mounts: /var/www/localhost/htdocs/openemr/sites (sites_fs),
                    /etc/ssl (ssl_fs).
        Environment variables injected at task definition time.

        Health check: HTTPS GET /openemr/login.php — 2xx/3xx = healthy.

        Returns:
            (FargateService, ApplicationTargetGroup)

        TODO Sprint 4.10:
            - TaskDefinition: cpu=512, memory_limit_mib=1024, runtime_platform=ARM64
            - Container: ECR_IMAGE_URI, portMappings=[CONTAINER_PORT/tcp]
            - Two EFS volumes + mount points
            - FargateService: desired_count=1, security_groups=[container_sg],
                vpc_subnets=PRIVATE_WITH_EGRESS
            - ApplicationTargetGroup: protocol=HTTPS, port=CONTAINER_PORT,
                health_check={path="/openemr/login.php", protocol=HTTPS}
            - Suppress AwsSolutions-ECS2 (secrets via task env, not plain-text)
        """
        raise NotImplementedError("TODO Sprint 4.10: implement create_fargate_service()")

    # ------------------------------------------------------------------ #
    # 4. ALB listener rule                                                 #
    # ------------------------------------------------------------------ #
    def add_listener_rule(
        self,
        listener: elbv2.ApplicationListener,
        target_group: elbv2.ApplicationTargetGroup,
        tenant_id: str,
        priority: int,
    ) -> elbv2.ApplicationListenerRule:
        """Add an HTTPS listener rule routing {tenant_id}.{DOMAIN} to the tenant service.

        Host header condition: f"{tenant_id}.{DOMAIN}"
        Priority must be unique across all tenants.

        Returns:
            ApplicationListenerRule

        TODO Sprint 4.11:
            - conditions=[ListenerCondition.host_headers([f"{tenant_id}.{DOMAIN}"])]
            - action=ListenerAction.forward([target_group])
        """
        raise NotImplementedError("TODO Sprint 4.11: implement add_listener_rule()")

    # ------------------------------------------------------------------ #
    # 5. Route 53 DNS                                                      #
    # ------------------------------------------------------------------ #
    def create_dns_record(
        self,
        hosted_zone: route53.IHostedZone,
        alb: elbv2.ApplicationLoadBalancer,
        tenant_id: str,
    ) -> route53.ARecord:
        """Create an A alias record pointing {tenant_id}.{DOMAIN} to the shared ALB.

        Returns:
            ARecord

        TODO Sprint 4.12:
            - record_name=f"{tenant_id}.{DOMAIN}"
            - target=RecordTarget.from_alias(LoadBalancerTarget(alb))
        """
        raise NotImplementedError("TODO Sprint 4.12: implement create_dns_record()")
