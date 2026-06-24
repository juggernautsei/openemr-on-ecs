"""Tenant Resources component — all per-tenant infrastructure created by TenantStack.

Each public method is called once per tenant deployment.

Build order (called from TenantStack.__init__):
  1. create_efs(vpc, kms_key, tenant_id)
  2. create_backup_plan(sites_fs, ssl_fs, tenant_id)      (Sprint 4.13)
  3. create_fargate_service(cluster, task_role, exec_role, tenant_id, aurora_secret_arn,
                           valkey_endpoint, sites_fs, ssl_fs, container_sg) (Sprint 4.14)
  4. add_listener_rule(listener, target_group, tenant_id, priority)          (Sprint 4.15)
  5. create_dns_record(hosted_zone, alb, tenant_id)                          (Sprint 4.15)
"""

from typing import Optional

from aws_cdk import RemovalPolicy
from aws_cdk import aws_backup as backup
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_efs as efs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_secretsmanager as secretsmanager
from cdk_nag import NagSuppressions
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
        self.efs_sg:   Optional[ec2.SecurityGroup] = None   # NFS ingress added in Sprint 4.14
        self.sites_fs: Optional[efs.FileSystem]    = None
        self.ssl_fs:   Optional[efs.FileSystem]    = None

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
    # 1. EFS (Sprint 4.12 — COMPLETE)                                     #
    # ------------------------------------------------------------------ #
    def create_efs(
        self,
        vpc: ec2.Vpc,
        kms_key: kms.Key,
        tenant_id: str,
    ) -> tuple[efs.FileSystem, efs.FileSystem]:
        """Create a pair of encrypted EFS file systems for this tenant.

        File systems:
            sites_fs: Mounts at ``/var/www/localhost/htdocs/openemr/sites``
                      inside the OpenEMR container.  Stores patient documents,
                      configuration, and any per-tenant custom modules loaded
                      at runtime.
            ssl_fs:   Mounts at ``/etc/ssl`` inside the container.  Stores
                      the per-tenant TLS certificate and private key so the
                      OpenEMR container can terminate HTTPS internally.

        Settings:
            encrypted: True — KMS CMK (platform key from SharedInfraStack).
            lifecycle_policy: AFTER_7_DAYS — move inactive files to the
                Infrequent Access (IA) storage class to reduce cost.
            out_of_infrequent_access_policy: AFTER_1_ACCESS — files
                promoted back to standard tier on first read, preventing
                repeated IA retrieval charges for active patient records.
            performance_mode: GENERAL_PURPOSE — lowest latency for
                OpenEMR's mixed small-file I/O pattern.
            throughput_mode: BURSTING — cost-effective for per-tenant
                workloads that do not sustain high baseline throughput.
            removal_policy: RETAIN — patient documents must survive any
                accidental stack deletion.

        Security group:
            A dedicated per-tenant EFS SG is created with no ingress rules.
            NFS (port 2049) inbound from the shared container SG is added
            by ``create_fargate_service()`` in Sprint 4.14 when both EFS
            and the task SG are in scope together.

        Automatic backups:
            Disabled here; a custom 7-year AWS Backup plan covering both
            EFS volumes is created in ``create_backup_plan()`` (Sprint 4.13)
            to meet HIPAA 7-year retention requirements.

        Returns:
            (sites_fs, ssl_fs)
        """
        # ---- Per-tenant EFS security group -----------------------------------
        # allow_all_outbound=False: EFS mount targets never initiate outbound
        # connections.  NFS ingress from the container SG is wired in Sprint 4.14.
        efs_sg = ec2.SecurityGroup(
            self.scope,
            f"{tenant_id.capitalize()}EfsSg",
            vpc=vpc,
            description=f"EFS mount target SG for tenant {tenant_id}",
            allow_all_outbound=False,
        )

        # ---- Common EFS props shared by both file systems --------------------
        _common: dict = dict(
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            security_group=efs_sg,
            encrypted=True,
            kms_key=kms_key,
            lifecycle_policy=efs.LifecyclePolicy.AFTER_7_DAYS,
            out_of_infrequent_access_policy=(
                efs.OutOfInfrequentAccessPolicy.AFTER_1_ACCESS
            ),
            performance_mode=efs.PerformanceMode.GENERAL_PURPOSE,
            throughput_mode=efs.ThroughputMode.BURSTING,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # ---- sites EFS -------------------------------------------------------
        sites_fs = efs.FileSystem(
            self.scope,
            f"{tenant_id.capitalize()}SitesFs",
            file_system_name=f"{tenant_id}-sites",
            **_common,
        )

        # ---- ssl EFS ---------------------------------------------------------
        ssl_fs = efs.FileSystem(
            self.scope,
            f"{tenant_id.capitalize()}SslFs",
            file_system_name=f"{tenant_id}-ssl",
            **_common,
        )

        # ---- Nag suppressions ------------------------------------------------
        # AwsSolutions-EFS1 + HIPAA.Security-EFSInBackupPlan:
        # Neither automatic EFS backups nor an AWS Backup plan exists yet.
        # A custom 7-year AWS Backup plan is created in create_backup_plan()
        # (Sprint 4.13), satisfying HIPAA 7-year retention.  EFS automatic
        # backups (max 35 days) are intentionally disabled in favour of the
        # custom plan.
        _backup_suppressions = [
            {
                "id": "AwsSolutions-EFS1",
                "reason": (
                    "Automatic EFS backups disabled intentionally.  A custom "
                    "7-year AWS Backup plan covering both volumes is created "
                    "in create_backup_plan() (Sprint 4.13) to meet HIPAA "
                    "retention requirements beyond the 35-day automatic window."
                ),
            },
            {
                "id": "HIPAA.Security-EFSInBackupPlan",
                "reason": (
                    "EFS volumes will be enrolled in a custom AWS Backup plan "
                    "with 7-year retention in create_backup_plan() (Sprint 4.13). "
                    "Plan creation is deferred to keep each sprint focused on "
                    "a single deliverable."
                ),
            },
        ]
        NagSuppressions.add_resource_suppressions(sites_fs, _backup_suppressions)
        NagSuppressions.add_resource_suppressions(ssl_fs,   _backup_suppressions)

        self.efs_sg   = efs_sg
        self.sites_fs = sites_fs
        self.ssl_fs   = ssl_fs
        return sites_fs, ssl_fs

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
