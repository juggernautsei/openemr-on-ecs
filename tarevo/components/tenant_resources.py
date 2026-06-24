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

from aws_cdk import Duration, RemovalPolicy
from aws_cdk import aws_backup as backup
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_efs as efs
from aws_cdk import aws_events as events
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_secretsmanager as secretsmanager
from cdk_nag import NagSuppressions
from constructs import Construct

from ..constants import (
    BACKUP_RETENTION_DAYS,
    CONTAINER_PORT,
    DOMAIN,
    ECR_IMAGE_URI,
    FARGATE_CPU,
    FARGATE_MEMORY,
    MYSQL_PORT,
    NFS_PORT,
    VALKEY_PORT,
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
        # AwsSolutions-EFS1: CDK does not propagate the AWS Backup plan
        # enrollment back to the EFS resource's BackupPolicy CloudFormation
        # attribute, so this rule fires even when EFS is enrolled in a plan.
        # Both volumes ARE covered by the custom 7-year plan created in
        # create_backup_plan() (Sprint 4.13).
        #
        # HIPAA.Security-EFSInBackupPlan: cdk-nag checks the EFS resource's
        # BackupPolicy attribute, not plan enrollment via BackupSelection.
        # The suppression is documented; the actual backup plan satisfies the
        # HIPAA requirement at deploy time.
        _backup_suppressions = [
            {
                "id": "AwsSolutions-EFS1",
                "reason": (
                    "Automatic EFS backups disabled; both volumes are enrolled "
                    "in a custom 7-year AWS Backup plan (create_backup_plan, "
                    "Sprint 4.13) that exceeds the 35-day automatic window. "
                    "CDK does not set BackupPolicy=ENABLED on the EFS resource "
                    "when enrolling via BackupSelection."
                ),
            },
            {
                "id": "HIPAA.Security-EFSInBackupPlan",
                "reason": (
                    "Both EFS volumes are enrolled in a custom 7-year AWS Backup "
                    "plan via BackupSelection (Sprint 4.13). cdk-nag checks the "
                    "EFS BackupPolicy attribute rather than BackupSelection "
                    "membership, so this finding persists despite actual coverage."
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
    # 2. Backup (Sprint 4.13 — COMPLETE)                                  #
    # ------------------------------------------------------------------ #
    def create_backup_plan(
        self,
        sites_fs: efs.FileSystem,
        ssl_fs: efs.FileSystem,
        tenant_id: str,
        kms_key: kms.IKey,
    ) -> backup.BackupPlan:
        """Create a 7-year HIPAA-compliant backup plan for tenant EFS volumes.

        Vault:
            A dedicated per-tenant backup vault encrypted with the platform
            KMS CMK.  ``RemovalPolicy.RETAIN`` prevents accidental loss of
            recovery points when a tenant stack is destroyed.

        Rule schedule and retention:
            Daily at 03:00 UTC (off-peak for clinics in US time zones).
            Move to cold storage after 90 days — reduces storage cost while
            keeping older backups accessible for compliance investigations.
            Delete after 2555 days (7 years) — satisfies HIPAA minimum
            retention for medical record backups (45 CFR 164.530(j)).
            1-hour start window; 3-hour completion window — generous
            windows for large OpenEMR sites directories.

        Selection:
            Both ``sites_fs`` (patient docs + config) and ``ssl_fs``
            (TLS certificates) are enrolled via a BackupSelection resource.

        Returns:
            BackupPlan
        """
        # ---- Per-tenant backup vault -----------------------------------------
        vault = backup.BackupVault(
            self.scope,
            f"{tenant_id.capitalize()}BackupVault",
            backup_vault_name=f"{tenant_id}-backup",
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # ---- Backup plan with custom 7-year rule -----------------------------
        plan = backup.BackupPlan(
            self.scope,
            f"{tenant_id.capitalize()}BackupPlan",
            backup_plan_name=f"{tenant_id}-efs-7yr",
            backup_plan_rules=[
                backup.BackupPlanRule(
                    backup_vault=vault,
                    rule_name=f"{tenant_id}-daily",
                    schedule_expression=events.Schedule.cron(
                        minute="0",
                        hour="3",
                    ),
                    start_window=Duration.hours(1),
                    completion_window=Duration.hours(3),
                    move_to_cold_storage_after=Duration.days(90),
                    delete_after=Duration.days(BACKUP_RETENTION_DAYS),
                ),
            ],
        )

        # ---- Enroll both EFS file systems ------------------------------------
        plan.add_selection(
            f"{tenant_id.capitalize()}EfsSelection",
            backup_selection_name=f"{tenant_id}-efs",
            resources=[
                backup.BackupResource.from_efs_file_system(sites_fs),
                backup.BackupResource.from_efs_file_system(ssl_fs),
            ],
        )

        # ---- Nag suppressions ------------------------------------------------
        # AwsSolutions-IAM4: CDK auto-creates an IAM service role for the
        # BackupSelection and attaches AWSBackupServiceRolePolicyForBackup.
        # This AWS-managed policy is the prescribed mechanism for granting AWS
        # Backup the permissions it needs; there is no narrower customer-managed
        # replacement that covers all required Backup API actions.
        NagSuppressions.add_resource_suppressions(
            plan,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": (
                        "AWSBackupServiceRolePolicyForBackup is the AWS-prescribed "
                        "managed policy for Backup service roles. No customer-managed "
                        "policy covers the full set of required Backup permissions."
                    ),
                    "applies_to": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/"
                        "service-role/AWSBackupServiceRolePolicyForBackup"
                    ],
                }
            ],
            apply_to_children=True,
        )

        self.backup_plan = plan
        return plan

    # ------------------------------------------------------------------ #
    # 3. Fargate service (Sprint 4.14 — COMPLETE)                         #
    # ------------------------------------------------------------------ #
    def create_fargate_service(
        self,
        vpc: ec2.IVpc,
        cluster: ecs.ICluster,
        tenant_id: str,
        kms_key: kms.IKey,
        aurora_secret_arn: str,
        aurora_endpoint: str,
        valkey_endpoint: str,
        sites_fs: efs.FileSystem,
        ssl_fs: efs.FileSystem,
        container_sg: ec2.ISecurityGroup,
        aurora_sg: ec2.ISecurityGroup,
        valkey_sg: ec2.ISecurityGroup,
    ) -> tuple[ecs.FargateService, elbv2.ApplicationTargetGroup]:
        """Create an ARM64 Fargate service running OpenEMR for this tenant.

        IAM:
            task_role  — application identity (ECS Exec / SSM Messages).
            exec_role  — ECS infrastructure identity (ECR pull, CloudWatch Logs
                write, Secrets Manager read for Aurora credentials).

        Container:
            Image:  ECR_IMAGE_URI constant (Tarevo-branded OpenEMR ARM64).
            Runtime: Linux ARM64 (Graviton) for cost efficiency.
            Port:   CONTAINER_PORT (443) — OpenEMR terminates TLS internally.
            EFS mounts:
                sites_fs → /var/www/localhost/htdocs/openemr/sites
                ssl_fs   → /etc/ssl
            Non-secret config injected via ``environment`` dict.
            Secrets (MySQL credentials) injected via ECS Secrets referencing
            Secrets Manager fields — never appear as plain-text env vars.

        Security-group wiring (deferred from create_efs; done here because
        this is the first point all SGs are in scope together):
            efs_sg    ← NFS (2049) from container_sg
            aurora_sg ← MySQL (3306) from container_sg
            valkey_sg ← Redis (6379) from container_sg

        Target group:
            HTTPS → port 443.  Health check: GET /openemr/login.php → 200–399.

        Returns:
            (FargateService, ApplicationTargetGroup)
        """
        # ---- Security-group wiring ------------------------------------------
        self.efs_sg.add_ingress_rule(
            container_sg,
            ec2.Port.tcp(NFS_PORT),
            "NFS from ECS container SG",
        )
        aurora_sg.add_ingress_rule(
            container_sg,
            ec2.Port.tcp(MYSQL_PORT),
            "MySQL from ECS container SG",
        )
        valkey_sg.add_ingress_rule(
            container_sg,
            ec2.Port.tcp(VALKEY_PORT),
            "Valkey from ECS container SG",
        )

        # ---- Container log group --------------------------------------------
        # Encrypted with the platform CMK; the key policy already grants
        # logs.{region}.amazonaws.com usage (AllowCloudWatchLogsEncryption
        # added by SecurityComponents.create_kms_key).
        log_group = logs.LogGroup(
            self.scope,
            f"{tenant_id.capitalize()}ContainerLogGroup",
            log_group_name=f"/tarevo/ecs/{tenant_id}",
            encryption_key=kms_key,
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # ---- Task execution role (ECS infrastructure) -----------------------
        # ECS uses this role (not the application) to pull images from ECR,
        # inject Secrets Manager values at container start, and write logs.
        exec_role = iam.Role(
            self.scope,
            f"{tenant_id.capitalize()}TaskExecRole",
            role_name=f"{tenant_id}-task-exec",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        )
        exec_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AmazonECSTaskExecutionRolePolicy"
            )
        )
        # Allow ECS to read the Aurora secret at container start
        exec_role.add_to_policy(
            iam.PolicyStatement(
                sid="ReadAuroraSecret",
                actions=["secretsmanager:GetSecretValue"],
                resources=[aurora_secret_arn],
            )
        )
        # Decrypt KMS-protected secret values
        exec_role.add_to_policy(
            iam.PolicyStatement(
                sid="DecryptSecretsKms",
                actions=["kms:Decrypt"],
                resources=[kms_key.key_arn],
            )
        )

        # ---- Task role (application identity) --------------------------------
        # Grants ECS Exec (break-glass shell access) via SSM Messages.
        task_role = iam.Role(
            self.scope,
            f"{tenant_id.capitalize()}TaskRole",
            role_name=f"{tenant_id}-task-role",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        )
        task_role.add_to_policy(
            iam.PolicyStatement(
                sid="EcsExecSsmMessages",
                actions=[
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel",
                ],
                resources=["*"],
            )
        )

        # ---- Fargate task definition ----------------------------------------
        task_def = ecs.FargateTaskDefinition(
            self.scope,
            f"{tenant_id.capitalize()}TaskDef",
            cpu=FARGATE_CPU,
            memory_limit_mib=FARGATE_MEMORY,
            task_role=task_role,
            execution_role=exec_role,
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.ARM64,
            ),
        )

        # ---- EFS volumes attached to the task definition --------------------
        task_def.add_volume(
            name="sites-volume",
            efs_volume_configuration=ecs.EfsVolumeConfiguration(
                file_system_id=sites_fs.file_system_id,
                transit_encryption="ENABLED",
            ),
        )
        task_def.add_volume(
            name="ssl-volume",
            efs_volume_configuration=ecs.EfsVolumeConfiguration(
                file_system_id=ssl_fs.file_system_id,
                transit_encryption="ENABLED",
            ),
        )

        # ---- Reconstruct Aurora secret from ARN Token -----------------------
        # aurora_secret_arn is a CDK Token (SSM-resolved at deploy time).
        # from_secret_complete_arn() accepts Token ARNs and produces a valid
        # ISecret that ecs.Secret.from_secrets_manager() can reference.
        aurora_secret = secretsmanager.Secret.from_secret_complete_arn(
            self.scope,
            f"{tenant_id.capitalize()}AuroraSecretRef",
            aurora_secret_arn,
        )

        # ---- Container definition -------------------------------------------
        # environment: non-secret infrastructure addresses only.
        #   No key name contains "password", "secret", or "key" — no ECS2 hit.
        # secrets:     Aurora credentials via Secrets Manager field references.
        #   ECS injects them as env vars at task start; never stored as plain text.
        container = task_def.add_container(
            "openemr",
            image=ecs.ContainerImage.from_registry(ECR_IMAGE_URI),
            container_name="openemr",
            memory_limit_mib=FARGATE_MEMORY,
            port_mappings=[
                ecs.PortMapping(
                    container_port=CONTAINER_PORT,
                    protocol=ecs.Protocol.TCP,
                )
            ],
            environment={
                "MYSQL_HOST":     aurora_endpoint,
                "MYSQL_PORT":     str(MYSQL_PORT),
                "MYSQL_DATABASE": tenant_id,
                "REDIS_SERVER":   valkey_endpoint,
                "REDIS_PORT":     str(VALKEY_PORT),
                "OE_SITE_DIR":    tenant_id,
            },
            secrets={
                "MYSQL_ROOT_PASSWORD": ecs.Secret.from_secrets_manager(
                    aurora_secret, field="password"
                ),
                "MYSQL_USER": ecs.Secret.from_secrets_manager(
                    aurora_secret, field="username"
                ),
                "MYSQL_PASS": ecs.Secret.from_secrets_manager(
                    aurora_secret, field="password"
                ),
            },
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix=f"openemr-{tenant_id}",
                log_group=log_group,
            ),
        )

        # ---- EFS mount points in the container ------------------------------
        container.add_mount_points(
            ecs.MountPoint(
                source_volume="sites-volume",
                container_path="/var/www/localhost/htdocs/openemr/sites",
                read_only=False,
            )
        )
        container.add_mount_points(
            ecs.MountPoint(
                source_volume="ssl-volume",
                container_path="/etc/ssl",
                read_only=False,
            )
        )

        # ---- Fargate service ------------------------------------------------
        service = ecs.FargateService(
            self.scope,
            f"{tenant_id.capitalize()}Service",
            service_name=f"{tenant_id}-openemr",
            cluster=cluster,
            task_definition=task_def,
            desired_count=1,
            min_healthy_percent=100,
            security_groups=[container_sg],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            enable_execute_command=True,
            assign_public_ip=False,
        )

        # ---- ALB target group -----------------------------------------------
        target_group = elbv2.ApplicationTargetGroup(
            self.scope,
            f"{tenant_id.capitalize()}TargetGroup",
            target_group_name=f"{tenant_id}-tg",
            vpc=vpc,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            port=CONTAINER_PORT,
            targets=[service],
            health_check=elbv2.HealthCheck(
                protocol=elbv2.Protocol.HTTPS,
                port=str(CONTAINER_PORT),
                path="/openemr/login.php",
                interval=Duration.seconds(30),
                timeout=Duration.seconds(10),
                healthy_threshold_count=2,
                unhealthy_threshold_count=5,
                healthy_http_codes="200-399",
            ),
            deregistration_delay=Duration.seconds(30),
        )

        # ---- Nag suppressions -----------------------------------------------
        #
        # exec_role: AmazonECSTaskExecutionRolePolicy (managed) + inline
        #   AwsSolutions-IAM4: AWS-prescribed managed policy for Fargate execution
        #     roles; no customer-managed alternative covers all required Fargate
        #     ECR-pull, CloudWatch Logs, and Secrets Manager permissions.
        #   AwsSolutions-IAM5: ecr:GetAuthorizationToken in the managed policy
        #     genuinely requires resource "*" — authorization tokens are not
        #     repository-scoped.
        #   HIPAA.Security-IAMNoInlinePolicy: CDK-generated DefaultPolicy scoped
        #     to the single Aurora secret ARN + KMS key — follows least privilege.
        NagSuppressions.add_resource_suppressions(
            exec_role,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": (
                        "AmazonECSTaskExecutionRolePolicy is the AWS-prescribed managed "
                        "policy for Fargate execution roles.  No customer-managed policy "
                        "covers all required ECR-pull, CloudWatch Logs, and Secrets Manager "
                        "Fargate infrastructure permissions."
                    ),
                    "applies_to": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/"
                        "service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "ecr:GetAuthorizationToken (from AmazonECSTaskExecutionRolePolicy) "
                        "genuinely requires resource '*' — ECR auth tokens are not "
                        "repository-scoped by design."
                    ),
                    "applies_to": ["Resource::*"],
                },
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "CDK DefaultPolicy on exec_role is scoped to the single Aurora "
                        "secret ARN and the platform KMS key — least-privilege inline "
                        "policy generated by CDK add_to_policy()."
                    ),
                },
            ],
            apply_to_children=True,
        )

        # task_role: inline SSM Messages policy (ECS Exec)
        #   AwsSolutions-IAM5: ssmmessages actions require "*" — the service
        #     does not support resource-level permission scoping.
        #   HIPAA.Security-IAMNoInlinePolicy: CDK DefaultPolicy for ECS Exec;
        #     follows the AWS ECS Exec documentation exactly.
        NagSuppressions.add_resource_suppressions(
            task_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "ssmmessages:* actions required for ECS Exec break-glass access "
                        "genuinely require resource '*' — SSM Messages does not support "
                        "resource-level permission scoping."
                    ),
                    "applies_to": ["Resource::*"],
                },
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": (
                        "CDK DefaultPolicy on task_role contains only the ECS Exec "
                        "ssmmessages actions as documented by AWS."
                    ),
                },
            ],
            apply_to_children=True,
        )

        # task_def: non-secret environment variables
        #   AwsSolutions-ECS2: environment dict contains only non-sensitive
        #     infrastructure addresses (host/port values).  All secret values
        #     (MySQL credentials) are injected via the ECS 'secrets' mechanism
        #     using Secrets Manager field references — not plain-text env vars.
        #   HIPAA.Security-ECSTaskDefinitionNoEnvironmentVariables: same
        #     justification as ECS2 — values are configuration, not credentials.
        NagSuppressions.add_resource_suppressions(
            task_def,
            [
                {
                    "id": "AwsSolutions-ECS2",
                    "reason": (
                        "environment dict contains only non-sensitive infrastructure "
                        "addresses (MySQL host/port, Redis host/port, OE_SITE_DIR).  "
                        "All MySQL credentials are injected via ECS Secrets (Secrets "
                        "Manager field references) and never appear as plain-text env vars."
                    ),
                },
                {
                    "id": "HIPAA.Security-ECSTaskDefinitionNoEnvironmentVariables",
                    "reason": (
                        "environment dict contains only non-sensitive infrastructure "
                        "addresses (MySQL host/port, Redis host/port, OE_SITE_DIR).  "
                        "MySQL credentials are injected via ECS Secrets (Secrets Manager "
                        "field references) and never appear as plain-text env vars."
                    ),
                },
            ],
            apply_to_children=True,
        )

        self.fargate_service = service
        self.target_group    = target_group
        return service, target_group

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
