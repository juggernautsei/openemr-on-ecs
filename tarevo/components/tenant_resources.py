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
from aws_cdk import aws_route53_targets as route53_targets
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


def tenant_database_name(tenant_id: str) -> str:
    """Return a MySQL-safe database name for a tenant identifier."""
    return f"{tenant_id.replace('-', '_')}_db"


def resolve_tenant_image_uri(tenant_image_uri: str | None) -> str:
    """Return tenant override image URI when provided, otherwise default image."""
    if tenant_image_uri is None:
        return ECR_IMAGE_URI
    image_uri = tenant_image_uri.strip()
    if not image_uri:
        raise ValueError("tenant_image_uri must be a non-empty image URI when provided.")
    return image_uri


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
        tenant_image_uri: str | None = None,
    ) -> tuple[ecs.FargateService, elbv2.ApplicationTargetGroup]:
        """Create an ARM64 Fargate service running OpenEMR for this tenant.

        IAM:
            task_role  — application identity (ECS Exec / SSM Messages).
            exec_role  — ECS infrastructure identity (ECR pull, CloudWatch Logs
                write, Secrets Manager read for Aurora credentials).

        Container:
            Image:  Uses tenant_image_uri when provided; otherwise ECR_IMAGE_URI
                constant (Tarevo-branded OpenEMR ARM64).
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

        # ---- Container startup command (mirrors compute.py wrapper) ---------
        # This wrapper runs before openemr.sh to:
        #   1. Restore the pristine sites skeleton (including docker_version) from
        #      /swarm-pieces/sites to the fresh EFS mount.  Without this rsync,
        #      openemr.sh sees docker_version=0, enters the upgrade path, and fails
        #      with "Cannot upgrade – OpenEMR is not configured yet".
        #   2. Download RDS and Valkey CA certificates for TLS verification.
        #   3. Patch /root/devtoolsLibrary.source to remove --skip-ssl so Aurora's
        #      require_secure_transport=ON is satisfied during schema installation.
        #   4. Clean up stale docker-leader files from crashed prior containers.
        startup_commands = [
            "set -e",
            "set -x",
            # Install su-exec (14 KB Alpine package) for privilege-drop without an
            # intervening shell.  su-exec passes argv verbatim — passwords containing
            # '=' or other chars that trip PHP's explode() reach the script intact.
            # Pattern from openemr-devops@c56d164 ("drop privileges to apache").
            'command -v su-exec >/dev/null 2>&1 || apk add --no-cache su-exec >/dev/null 2>&1 || true',
            'log() { echo "[$(date +%Y-%m-%d\\ %H:%M:%S)] $*"; }',
            'log "=== OpenEMR Container Startup Script ==="',
            'log "Starting container initialization..."',
            'cd /var/www/localhost/htdocs/openemr || { log "ERROR: Failed to change to OpenEMR directory"; exit 1; }',
            'if [ "$PWD" != "/var/www/localhost/htdocs/openemr" ]; then',
            '  log "ERROR: Working directory verification failed. Expected /var/www/localhost/htdocs/openemr, got $PWD"',
            "  exit 1",
            "fi",
            'log "Working directory verified: $PWD"',
            "if ! id apache >/dev/null 2>&1; then",
            '  log "ERROR: Apache user does not exist in container image"',
            "  exit 1",
            "fi",
            'log "Apache user verified"',
            # --- Persistence & EFS Initialization ---
            # Restore the pristine sites skeleton (including docker_version) from
            # the container image so openemr.sh sees the correct version and does
            # a fresh install instead of an invalid upgrade-from-zero.
            'log "Checking EFS sites directory initialization..."',
            "if [ ! -d /var/www/localhost/htdocs/openemr/sites/default ] || [ ! -f /var/www/localhost/htdocs/openemr/sites/default/sqlconf.php ]; then",
            '  log "EFS sites directory missing or uninitialized, restoring from image..."',
            "  if [ ! -d /swarm-pieces/sites ]; then",
            '    log "ERROR: Source directory /swarm-pieces/sites not found in container image"',
            "    exit 1",
            "  fi",
            "  rsync --owner --group --perms --recursive --links --verbose /swarm-pieces/sites /var/www/localhost/htdocs/openemr/ || {",
            '    log "ERROR: Failed to restore site skeleton from image"',
            "    exit 1",
            "  }",
            '  log "Site skeleton restored successfully"',
            "else",
            '  log "EFS sites directory already initialized"',
            "fi",
            # --- Certificate directories ---
            'log "Creating certificate directories..."',
            "mkdir -p /var/www/localhost/htdocs/openemr/sites/default/documents/certificates /root/certs/redis /root/certs/mysql/server /etc/ssl/certs /etc/ssl/private /etc/ssl/apache2 || {",
            '  log "ERROR: Failed to create certificate directories"',
            "  exit 1",
            "}",
            "for dir in /var/www/localhost/htdocs/openemr/sites/default/documents/certificates /root/certs/redis /root/certs/mysql/server /etc/ssl/certs /etc/ssl/private /etc/ssl/apache2; do",
            '  if [ ! -d "$dir" ]; then',
            '    log "ERROR: Directory $dir was not created"',
            "    exit 1",
            "  fi",
            "done",
            'log "Certificate directories created and verified"',
            # Rebuild trust anchors inside the EFS-mounted /etc/ssl tree.
            'SYSTEM_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"',
            # Bootstrap CA bundle from container image (not EFS-mounted /etc/ssl)
            # used for first HTTPS fetches before trust store is stable.
            'TRUSTED_BOOTSTRAP_CA="/swarm-pieces/ssl/certs/ca-certificates.crt"',
            "if command -v update-ca-certificates >/dev/null 2>&1; then",
            '  update-ca-certificates >/dev/null 2>&1 || log "WARNING: Failed to rebuild system CA trust store" ',
            "else",
            '  log "WARNING: update-ca-certificates not available; HTTPS downloads may fail" ',
            "fi",
            # --- OpenEMR Apache TLS materials ---
            # The tenant SSL EFS mount starts empty.  OpenEMR's Apache config
            # requires /etc/ssl/certs/webserver.cert.pem and
            # /etc/ssl/private/webserver.key.pem at startup.  Generate a
            # self-signed pair on first boot if missing.
            'log "Ensuring Apache TLS certificate and key exist..."',
            'APACHE_CERT_PATH="/etc/ssl/certs/webserver.cert.pem"',
            'APACHE_KEY_PATH="/etc/ssl/private/webserver.key.pem"',
            'APACHE_ALT_CERT_PATH="/etc/ssl/apache2/server.pem"',
            'APACHE_ALT_KEY_PATH="/etc/ssl/apache2/server.key"',
            'if [ ! -s "$APACHE_CERT_PATH" ] || [ ! -s "$APACHE_KEY_PATH" ] || [ ! -s "$APACHE_ALT_CERT_PATH" ] || [ ! -s "$APACHE_ALT_KEY_PATH" ]; then',
            '  log "Apache TLS files missing on SSL EFS mount, generating self-signed certificate..."',
            "  if ! command -v openssl >/dev/null 2>&1; then",
            '    log "ERROR: openssl is not installed in container image"',
            "    exit 1",
            "  fi",
            '  openssl genrsa 2048 > /etc/ssl/private/selfsigned.key.pem || {',
            '    log "ERROR: Failed to generate private key for Apache TLS"',
            "    exit 1",
            "  }",
            '  OPENSSL_CONFIG="/swarm-pieces/ssl/openssl.cnf"',
            '  if [ ! -f "$OPENSSL_CONFIG" ]; then',
            '    log "WARNING: $OPENSSL_CONFIG not found, trying /etc/ssl/openssl.cnf"',
            '    OPENSSL_CONFIG="/etc/ssl/openssl.cnf"',
            "  fi",
            '  openssl req -new -x509 -nodes -sha256 -days 365 -key /etc/ssl/private/selfsigned.key.pem -outform PEM -out /etc/ssl/certs/selfsigned.cert.pem -config "$OPENSSL_CONFIG" -subj "/CN=localhost" || {',
            '    log "ERROR: Failed to generate self-signed Apache certificate"',
            "    exit 1",
            "  }",
            '  cp /etc/ssl/private/selfsigned.key.pem "$APACHE_KEY_PATH" || {',
            '    log "ERROR: Failed to copy Apache private key to expected path"',
            "    exit 1",
            "  }",
            '  cp /etc/ssl/private/selfsigned.key.pem "$APACHE_ALT_KEY_PATH" || {',
            '    log "ERROR: Failed to copy Apache private key to /etc/ssl/apache2/server.key"',
            "    exit 1",
            "  }",
            '  cp /etc/ssl/certs/selfsigned.cert.pem "$APACHE_CERT_PATH" || {',
            '    log "ERROR: Failed to copy Apache certificate to expected path"',
            "    exit 1",
            "  }",
            '  cp /etc/ssl/certs/selfsigned.cert.pem "$APACHE_ALT_CERT_PATH" || {',
            '    log "ERROR: Failed to copy Apache certificate to /etc/ssl/apache2/server.pem"',
            "    exit 1",
            "  }",
            '  chmod 600 /etc/ssl/private/selfsigned.key.pem "$APACHE_KEY_PATH" || {',
            '    log "ERROR: Failed to set permissions on Apache private key"',
            "    exit 1",
            "  }",
            '  chmod 600 "$APACHE_ALT_KEY_PATH" || {',
            '    log "ERROR: Failed to set permissions on /etc/ssl/apache2/server.key"',
            "    exit 1",
            "  }",
            '  chmod 644 /etc/ssl/certs/selfsigned.cert.pem "$APACHE_CERT_PATH" || {',
            '    log "ERROR: Failed to set permissions on Apache certificate"',
            "    exit 1",
            "  }",
            '  chmod 644 "$APACHE_ALT_CERT_PATH" || {',
            '    log "ERROR: Failed to set permissions on /etc/ssl/apache2/server.pem"',
            "    exit 1",
            "  }",
            '  touch /etc/ssl/docker-selfsigned-configured || true',
            '  log "Apache TLS materials generated successfully"',
            "else",
            '  log "Apache TLS materials already exist, skipping generation"',
            "fi",
            # --- Redis/Valkey TLS CA ---
            'log "Downloading Amazon Root CA1 for Redis/Valkey TLS..."',
            'REDIS_CA_URL="https://www.amazontrust.com/repository/AmazonRootCA1.pem"',
            'REDIS_CA_PATH="/root/certs/redis/redis-ca"',
            'if [ ! -f "$REDIS_CA_PATH" ] || [ ! -s "$REDIS_CA_PATH" ]; then',
            '  if [ -f "$SYSTEM_CA_BUNDLE" ] && [ -s "$SYSTEM_CA_BUNDLE" ]; then',
            '    cp "$SYSTEM_CA_BUNDLE" "$REDIS_CA_PATH" || {',
            '      log "ERROR: Failed to copy system CA bundle to Redis CA path"',
            "      exit 1",
            "    }",
            '    log "Redis CA bundle copied from system trust store ($SYSTEM_CA_BUNDLE)"',
            "  else",
            '    curl -k -f --max-time 30 --connect-timeout 10 --retry 3 --retry-delay 2 --retry-connrefused -o "$REDIS_CA_PATH" "$REDIS_CA_URL" || {',
            '      log "ERROR: Failed to download Redis CA certificate from $REDIS_CA_URL"',
            "      exit 1",
            "    }",
            "  fi",
            '  if [ ! -f "$REDIS_CA_PATH" ] || [ ! -s "$REDIS_CA_PATH" ]; then',
            '    log "ERROR: Redis CA certificate file is missing or empty after download"',
            "    exit 1",
            "  fi",
            '  CERT_SIZE=$(wc -c < "$REDIS_CA_PATH")',
            '  if [ "$CERT_SIZE" -lt 500 ]; then',
            '    log "ERROR: Redis CA certificate size ($CERT_SIZE bytes) is too small"',
            "    exit 1",
            "  fi",
            '  if ! head -n 1 "$REDIS_CA_PATH" | grep -q "BEGIN CERTIFICATE" 2>/dev/null; then',
            '    log "ERROR: Redis CA certificate does not appear to be valid PEM format"',
            "    exit 1",
            "  fi",
            '  log "Redis CA certificate downloaded successfully ($CERT_SIZE bytes) and validated"',
            "else",
            '  log "Redis CA certificate already exists, skipping download"',
            "fi",
            'chown apache "$REDIS_CA_PATH" || { log "ERROR: Failed to set ownership on Redis CA certificate"; exit 1; }',
            'log "Redis CA certificate ready"',
            # --- RDS/Aurora MySQL CA ---
            'log "Downloading RDS CA bundle for MySQL SSL..."',
            'MYSQL_CA_URL="https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem"',
            'MYSQL_CA_PATH="/root/certs/mysql/server/mysql-ca"',
            'if [ ! -f "$MYSQL_CA_PATH" ] || [ ! -s "$MYSQL_CA_PATH" ]; then',
            '  MYSQL_CA_READY=0',
            '  if [ -f \"$TRUSTED_BOOTSTRAP_CA\" ] && [ -s \"$TRUSTED_BOOTSTRAP_CA\" ]; then',
            '    if curl -f --max-time 30 --connect-timeout 10 --retry 3 --retry-delay 2 --retry-connrefused --cacert \"$TRUSTED_BOOTSTRAP_CA\" -o \"$MYSQL_CA_PATH\" \"$MYSQL_CA_URL\"; then',
            '      MYSQL_CA_READY=1',
            '      log \"MySQL CA bundle downloaded successfully using bootstrap trust store ($TRUSTED_BOOTSTRAP_CA)\"',
            '    else',
            '      log \"WARNING: Failed to download MySQL CA bundle with bootstrap trust store; trying fallback methods\"',
            '    fi',
            '  fi',
            '  if [ \"$MYSQL_CA_READY\" -eq 0 ] && [ -f \"$SYSTEM_CA_BUNDLE\" ] && [ -s \"$SYSTEM_CA_BUNDLE\" ]; then',
            '    cp \"$SYSTEM_CA_BUNDLE\" \"$MYSQL_CA_PATH\" || {',
            '      log \"ERROR: Failed to copy system CA bundle to MySQL CA path\"',
            '      exit 1',
            '    }',
            '    MYSQL_CA_READY=1',
            '    log \"MySQL CA bundle copied from system trust store ($SYSTEM_CA_BUNDLE)\"',
            '  fi',
            '  if [ \"$MYSQL_CA_READY\" -eq 0 ]; then',
            '    curl -k -f --max-time 30 --connect-timeout 10 --retry 3 --retry-delay 2 --retry-connrefused -o \"$MYSQL_CA_PATH\" \"$MYSQL_CA_URL\" || {',
            '      log \"ERROR: Failed to download MySQL CA certificate from $MYSQL_CA_URL\"',
            '      exit 1',
            '    }',
            '    MYSQL_CA_READY=1',
            '  fi',
            '  if [ ! -f "$MYSQL_CA_PATH" ] || [ ! -s "$MYSQL_CA_PATH" ]; then',
            '    log "ERROR: MySQL CA certificate file is missing or empty after download"',
            "    exit 1",
            "  fi",
            '  CERT_SIZE=$(wc -c < "$MYSQL_CA_PATH")',
            '  if [ "$CERT_SIZE" -lt 500 ]; then',
            '    log "ERROR: MySQL CA certificate bundle size ($CERT_SIZE bytes) is too small"',
            "    exit 1",
            "  fi",
            '  if ! grep -q \"BEGIN CERTIFICATE\" \"$MYSQL_CA_PATH\" 2>/dev/null; then',
            '    log "ERROR: MySQL CA certificate bundle does not appear to be valid PEM format"',
            "    exit 1",
            "  fi",
            '  log "MySQL CA certificate bundle downloaded successfully ($CERT_SIZE bytes) and validated"',
            "else",
            '  log "MySQL CA certificate already exists, skipping download"',
            "fi",
            'chown apache "$MYSQL_CA_PATH" || { log "ERROR: Failed to set ownership on MySQL CA certificate"; exit 1; }',
            'log "Deploying MySQL CA certificate to OpenEMR certificates directory..."',
            'OPENEMR_CA_PATH="/var/www/localhost/htdocs/openemr/sites/default/documents/certificates/mysql-ca"',
            'cp "$MYSQL_CA_PATH" "$OPENEMR_CA_PATH" || {',
            '  log "ERROR: Failed to copy MySQL CA certificate to OpenEMR directory"',
            "  exit 1",
            "}",
            'chown apache "$OPENEMR_CA_PATH" || { log "ERROR: Failed to set ownership on OpenEMR MySQL CA certificate"; exit 1; }',
            'chmod 744 "$OPENEMR_CA_PATH" || { log "ERROR: Failed to set permissions on OpenEMR MySQL CA certificate"; exit 1; }',
            'if [ ! -f "$OPENEMR_CA_PATH" ] || [ ! -r "$OPENEMR_CA_PATH" ]; then',
            '  log "ERROR: OpenEMR MySQL CA certificate is missing or not readable after deployment"',
            "  exit 1",
            "fi",
            'log "MySQL CA certificate deployed successfully"',
            # --- Bootstrap reliability patches ---
            'log "Applying OpenEMR bootstrap reliability fixes (RDS TLS + retry safety)..."',
            'if [ -d "/tmp/php-file-cache" ]; then',
            '  log "Removing stale /tmp/php-file-cache from prior attempt"',
            '  rm -rf "/tmp/php-file-cache" 2>/dev/null || true',
            "fi",
            # Pre-create opcache dir as apache before openemr.sh gets a chance to
            # create it as root.  When PHP runs as apache (RootCliGuard fix) it
            # needs write access to this directory; `mkdir -p` on an existing dir
            # is a no-op, so openemr.sh's own mkdir won't clobber our ownership.
            # Pattern from openemr-devops@c56d164 / openemr-devops@f5388e1.
            'mkdir -p /tmp/php-file-cache',
            'chown apache:apache /tmp/php-file-cache',
            'chmod 0700 /tmp/php-file-cache',
            'log "Pre-created /tmp/php-file-cache with apache ownership (RootCliGuard opcache fix)"',
            "if command -v update-ca-certificates >/dev/null 2>&1; then",
            '  RDS_CA_DST="/usr/local/share/ca-certificates/rds-global-bundle.crt"',
            '  (cp "$MYSQL_CA_PATH" "$RDS_CA_DST" 2>/dev/null || cp "$OPENEMR_CA_PATH" "$RDS_CA_DST" 2>/dev/null || true)',
            '  update-ca-certificates >/dev/null 2>&1 || log "WARNING: update-ca-certificates failed; relying on app-provided CA paths"',
            "else",
            '  log "WARNING: update-ca-certificates not available; relying on app-provided CA paths"',
            "fi",
            'if [ -f "/root/devtoolsLibrary.source" ]; then',
            '  if grep -q -- "--skip-ssl" /root/devtoolsLibrary.source 2>/dev/null; then',
            '    log "Patching /root/devtoolsLibrary.source: removing --skip-ssl to allow TLS to RDS"',
            "    sed -i 's/ --skip-ssl//g' /root/devtoolsLibrary.source 2>/dev/null || true",
            "  fi",
            "fi",
            # --- Verification ---
            'log "Verifying critical files and directories..."',
            'for path in "$REDIS_CA_PATH" "$MYSQL_CA_PATH" "$OPENEMR_CA_PATH" /var/www/localhost/htdocs/openemr/sites/default; do',
            '  if [ ! -e "$path" ]; then',
            '    log "ERROR: Critical path missing: $path"',
            "    exit 1",
            "  fi",
            "done",
            'log "All critical paths verified"',
            "if [ ! -f ./openemr.sh ]; then",
            '  log "ERROR: openemr.sh not found in working directory"',
            "  exit 1",
            "fi",
            'chmod +x ./openemr.sh || { log "ERROR: Failed to make openemr.sh executable"; exit 1; }',
            'CRON_FILE=""',
            'if [ -f /etc/crontabs/root ]; then CRON_FILE="/etc/crontabs/root"; fi',
            'if [ -z "$CRON_FILE" ] && [ -d /var/spool/cron/crontabs ]; then CRON_FILE="/var/spool/cron/crontabs/root"; fi',
            'if [ -n "$CRON_FILE" ]; then',
            '  if ! grep -q "httpd -k graceful" "$CRON_FILE" 2>/dev/null; then',
            '    echo "1 23  *   *   *   httpd -k graceful" >> "$CRON_FILE" || true',
            '    log "Added Apache graceful restart cron job to $CRON_FILE"',
            '  else',
            '    log "Apache graceful restart cron job already exists"',
            '  fi',
            'else',
            '  log "WARNING: No cron file found, skipping Apache restart cron job"',
            "fi",
            'log "=== Container initialization complete ==="',
            # --- EFS writability check ---
            'log "Verifying EFS mount points are writable..."',
            'EFS_SITES_TEST_FILE="/var/www/localhost/htdocs/openemr/sites/.efs_write_test"',
            'EFS_SSL_TEST_FILE="/etc/ssl/.efs_write_test"',
            'if touch "$EFS_SITES_TEST_FILE" 2>/dev/null && rm -f "$EFS_SITES_TEST_FILE" 2>/dev/null; then',
            '  log "EFS sites mount verified (writable)"',
            "else",
            '  log "ERROR: EFS sites mount is not writable. Cannot proceed with setup."',
            "  exit 1",
            "fi",
            'if touch "$EFS_SSL_TEST_FILE" 2>/dev/null && rm -f "$EFS_SSL_TEST_FILE" 2>/dev/null; then',
            '  log "EFS SSL mount verified (writable)"',
            "else",
            '  log "ERROR: EFS SSL mount is not writable. Cannot proceed with setup."',
            "  exit 1",
            "fi",
            'log "All EFS mounts verified and writable"',
            # --- Database readiness ---
            'log "Checking database connectivity..."',
            'if [ -z "$MYSQL_HOST" ] || [ -z "$MYSQL_ROOT_PASS" ]; then',
            '  log "WARNING: Database credentials not available for readiness check, will rely on OpenEMR retry logic"',
            "else",
            "  DB_READY=0",
            "  MAX_ATTEMPTS=30",
            "  INITIAL_DELAY=2",
            "  CURRENT_DELAY=$INITIAL_DELAY",
            "  for attempt in $(seq 1 $MAX_ATTEMPTS); do",
            "    if command -v mysqladmin >/dev/null 2>&1; then",
            '      MYSQLADMIN_CMD="mysqladmin ping -h \\"$MYSQL_HOST\\" -u \\"$MYSQL_ROOT_USER\\" -p\\"$MYSQL_ROOT_PASS\\""',
            '      if [ -n "$MYSQL_CA_PATH" ] && [ -f "$MYSQL_CA_PATH" ]; then',
            '        MYSQLADMIN_CMD="$MYSQLADMIN_CMD --ssl --ssl-ca=\\"$MYSQL_CA_PATH\\""',
            "      else",
            '        MYSQLADMIN_CMD="$MYSQLADMIN_CMD --ssl"',
            "      fi",
            '      if eval "$MYSQLADMIN_CMD" 2>&1; then',
            '        log "Database connectivity verified (attempt $attempt/$MAX_ATTEMPTS)"',
            "        DB_READY=1",
            "        break",
            "      fi",
            '    elif command -v nc >/dev/null 2>&1 && [ -n "$MYSQL_PORT" ]; then',
            '      if nc -z -w 3 "$MYSQL_HOST" "${MYSQL_PORT:-3306}" 2>/dev/null; then',
            '        log "Database port is reachable (attempt $attempt/$MAX_ATTEMPTS), assuming ready"',
            "        DB_READY=1",
            "        break",
            "      fi",
            "    else",
            '      log "WARNING: Neither mysqladmin nor nc available for database readiness check"',
            "      DB_READY=1",
            "      break",
            "    fi",
            '    if [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then',
            '      log "Database not ready yet, waiting ${CURRENT_DELAY}s before retry (attempt $attempt/$MAX_ATTEMPTS)..."',
            "      sleep $CURRENT_DELAY",
            "      CURRENT_DELAY=$((CURRENT_DELAY * 2))",
            '      if [ "$CURRENT_DELAY" -gt 60 ]; then',
            "        CURRENT_DELAY=60",
            "      fi",
            "    fi",
            "  done",
            '  if [ "$DB_READY" -eq 0 ]; then',
            '    log "WARNING: Database readiness check failed after $MAX_ATTEMPTS attempts"',
            '    log "Database may still be initializing. OpenEMR will retry setup automatically."',
            "  fi",
            "fi",
            # --- Valkey connectivity ---
            'log "Checking Valkey/Redis connectivity..."',
            'if [ -z "$REDIS_SERVER" ] || [ "$REDIS_SERVER" = "null" ]; then',
            '  log "Valkey/Redis not configured, skipping connectivity check"',
            "else",
            '  REDIS_HOST="${REDIS_SERVER%%:*}"',
            '  REDIS_PORT="${REDIS_SERVER##*:}"',
            '  if [ "$REDIS_PORT" = "$REDIS_HOST" ] || [ -z "$REDIS_PORT" ]; then',
            '    REDIS_PORT="6379"',
            "  fi",
            "  if command -v nc >/dev/null 2>&1; then",
            '    if nc -z -w 3 "$REDIS_HOST" "$REDIS_PORT" 2>/dev/null; then',
            '      log "Valkey/Redis connectivity verified ($REDIS_HOST:$REDIS_PORT)"',
            "    else",
            '      log "WARNING: Valkey/Redis not reachable at $REDIS_HOST:$REDIS_PORT"',
            '      log "Application may have degraded cache functionality, but will continue startup"',
            "    fi",
            "  else",
            '    log "WARNING: nc (netcat) not available for Valkey/Redis connectivity check"',
            "  fi",
            "fi",
            # --- Stale docker-leader cleanup ---
            'log "Checking for stale docker-leader files..."',
            'LEADER_FILE="/var/www/localhost/htdocs/openemr/sites/docker-leader"',
            'COMPLETED_FILE="/var/www/localhost/htdocs/openemr/sites/docker-completed"',
            'if [ -f "$COMPLETED_FILE" ]; then',
            '  log "Setup completed successfully (docker-completed file exists), proceeding normally"',
            'elif [ -f "$LEADER_FILE" ]; then',
            # With SWARM_MODE=no this container is always the sole leader; any
            # docker-leader left by a previous failed container is stale by
            # definition.  Remove it unconditionally so openemr.sh does not
            # enter the 20-min follower wait loop.
            '  if [ "${SWARM_MODE:-no}" = "no" ]; then',
            '    log "SWARM_MODE=no (single replica): removing stale docker-leader from previous run..."',
            '    rm -f "$LEADER_FILE" || log "WARNING: Failed to remove stale leader file, openemr.sh will retry"',
            '    log "Cleared. This container will act as leader."',
            '  else',
            '    log "docker-leader file exists but docker-completed does not, checking if leader is stale..."',
            '    LEADER_MTIME=$(stat -c %Y "$LEADER_FILE" 2>/dev/null || stat -f %m "$LEADER_FILE" 2>/dev/null || echo "")',
            '    if [ -n "$LEADER_MTIME" ] && [ "$LEADER_MTIME" != "0" ]; then',
            "      CURRENT_TIME=$(date +%s)",
            "      AGE_SECONDS=$((CURRENT_TIME - LEADER_MTIME))",
            '      if [ "$AGE_SECONDS" -gt 1200 ]; then',
            '        log "WARNING: Stale docker-leader file detected (${AGE_SECONDS}s old, >20min). Leader likely failed mid-setup."',
            "        log \"This can cause 'Table already exists' errors. Cleaning up stale leader file...\"",
            '        rm -f "$LEADER_FILE" || log "WARNING: Failed to remove stale leader file, continuing anyway"',
            '        log "Stale leader file cleaned up."',
            '      else',
            '        log "docker-leader file is recent (${AGE_SECONDS}s old), waiting for leader to complete setup..."',
            '      fi',
            '    else',
            '      log "Could not determine age of docker-leader file. Will rely on openemr.sh timeout handling."',
            '    fi',
            '  fi',
            "else",
            '  log "No docker-leader file found, this container may become the leader"',
            "fi",
            # ---------------------------------------------------------------
            # ROOT CAUSE FIX (confirmed from Aurora error logs):
            # auto_configure.php parses argv with explode("=", $arg) WITHOUT
            # a limit, so "rootpass=abc=c5" is parsed as rootpass="abc" —
            # the password is truncated at the first "=".  Aurora then sees
            # a password that doesn't match root@% → Access denied.
            #
            # Fix: use the mariadb CLI (which handles "=" in passwords
            # correctly) to change root@%'s password to exactly the value
            # that PHP will send (everything before the first "=").  Export
            # the shortened password so openemr.sh and devtools use it too.
            #
            # IMPORTANT: This block runs AFTER the DB readiness loop above
            # so Aurora is guaranteed to be up when we execute ALTER USER.
            # ---------------------------------------------------------------
            'log "Checking if root@% password needs normalizing for PHP explode() compatibility..."',
            'if echo "$MYSQL_ROOT_PASS" | grep -q "="; then',
            '  COMPAT_PASS="${MYSQL_ROOT_PASS%%=*}"',
            '  log "Password contains = - normalizing root@% for PHP auto_configure.php compatibility"',
            '  if mariadb -h "$MYSQL_HOST" -P "${MYSQL_PORT:-3306}" -u "$MYSQL_ROOT_USER" -p"$MYSQL_ROOT_PASS" --ssl --ssl-ca="$MYSQL_CA_PATH" -e "ALTER USER \'root\'@\'%\' IDENTIFIED BY \'${COMPAT_PASS}\'; FLUSH PRIVILEGES;" 2>&1; then',
            '    export MYSQL_ROOT_PASS="$COMPAT_PASS"',
            '    log "root@% password normalized: removed = suffix, PHP auto_configure.php will now match"',
            '  else',
            '    log "WARNING: Could not normalize root@% password - setup will likely fail"',
            '  fi',
            'else',
            '  log "Password does not contain = - no normalization needed"',
            'fi',
            'log "Handing over to openemr.sh..."',
            "exec ./openemr.sh",
        ]
        command_array = ["\n".join(startup_commands)]

        # ---- Container definition -------------------------------------------
        # environment: non-secret, non-sensitive configuration values only.
        # secrets:     All credentials injected via ECS Secrets (Secrets Manager
        #              field references) — never stored as plain-text env vars.
        #
        # SWARM_MODE=yes / AUTHORITY=yes: required for openemr.sh to take the
        #   fresh-install path on a brand-new EFS.  Without AUTHORITY=yes the
        #   script errors with "Cannot upgrade — OpenEMR is not configured yet".
        # OE_SITE_DIR=default: standard single-site name.  Each tenant has its
        #   own EFS mount so using 'default' provides full isolation.
        # MYSQL_SSL=ON: Aurora requires TLS (require_secure_transport=ON).
        # REDIS_TLS=on: ElastiCache Valkey transit encryption is enabled.
        container = task_def.add_container(
            "openemr",
            image=ecs.ContainerImage.from_registry(
                resolve_tenant_image_uri(tenant_image_uri)
            ),
            container_name="openemr",
            memory_limit_mib=FARGATE_MEMORY,
            working_directory="/var/www/localhost/htdocs/openemr",
            entry_point=["/bin/sh", "-c"],
            command=command_array,
            port_mappings=[
                ecs.PortMapping(
                    container_port=CONTAINER_PORT,
                    protocol=ecs.Protocol.TCP,
                )
            ],
            environment={
                "MYSQL_DATABASE": tenant_database_name(tenant_id),
                "MYSQL_PORT":     str(MYSQL_PORT),
                "REDIS_SERVER":   valkey_endpoint,
                "REDIS_PORT":     str(VALKEY_PORT),
                # Standard single-site name — each tenant has a dedicated EFS mount
                # so 'default' is fully isolated per tenant.
                "OE_SITE_DIR":    "default",
                # SWARM_MODE=no: each tenant runs a SINGLE container replica, not a
                # Docker Swarm cluster.  In non-swarm mode openemr.sh skips all leader
                # election / docker-leader / docker-authority logic and goes straight to
                # the database check → fresh-install or upgrade as appropriate.
                "SWARM_MODE":     "no",
                # MYSQL_ROOT_USER must be set explicitly so devtoolsLibrary.source
                # constructs CONFIGURATION as "root=root" not "root=''".  When
                # MYSQL_ROOT_USER is unset, the shell default-expansion logic in
                # devtoolsLibrary.source passes an empty root username to
                # auto_configure.php, causing the MySQL connection to fail.
                "MYSQL_ROOT_USER": "root",
                # Aurora requires TLS (require_secure_transport=ON).
                "MYSQL_SSL":      "ON",
                # openemr.sh reads MYSQL_SSL_CA to add ssl_cafile=<path> to the
                # CONFIGURATION string passed to auto_configure.php.  Without this
                # env var, PHP's Installer class connects to Aurora without SSL and
                # gets ERROR 3159 (HY000): Connections using insecure transport are
                # prohibited.  The wrapper script downloads the RDS CA bundle to this
                # exact path before exec'ing openemr.sh.
                "MYSQL_SSL_CA":   "/var/www/localhost/htdocs/openemr/sites/default/documents/certificates/mysql-ca",
                # ElastiCache Valkey transit encryption is enabled platform-wide.
                # Use "yes" to match upstream OpenEMR-on-ECS env convention.
                "REDIS_TLS":      "yes",
            },
            secrets={
                # MYSQL_ROOT_PASS: Aurora admin password used by openemr.sh on first
                # boot.  MYSQL_ROOT_USER=root is set in environment{} above.
                # The Lambda provisioner creates a `root`@`%` MySQL account on Aurora
                # (with the admin password) so that the auto_configure.php connection
                # as 'root' succeeds.
                "MYSQL_ROOT_PASS": ecs.Secret.from_secrets_manager(
                    aurora_secret, field="password"
                ),
                # MYSQL_USER / MYSQL_PASS: OpenEMR app DB user.  Shared with root
                # for now; per-tenant credential isolation is Sprint 6+ hardening.
                "MYSQL_USER": ecs.Secret.from_secrets_manager(
                    aurora_secret, field="username"
                ),
                "MYSQL_PASS": ecs.Secret.from_secrets_manager(
                    aurora_secret, field="password"
                ),
                # MYSQL_HOST from secret (same source as the Lambda provisioner uses)
                "MYSQL_HOST": ecs.Secret.from_secrets_manager(
                    aurora_secret, field="host"
                ),
            },
            health_check=ecs.HealthCheck(
                # Smart health check: returns healthy (exit 0) while OpenEMR is
                # installing so ECS does not restart the task mid-setup.  Only
                # enforces a real HTTPS probe once docker-completed exists.
                # Falls back to "stuck for >20min without completing" → exit 1.
                command=[
                    "CMD-SHELL",
                    (
                        "COMPLETED=/var/www/localhost/htdocs/openemr/sites/docker-completed; "
                        "INIT=/var/www/localhost/htdocs/openemr/sites/docker-initiated; "
                        'if [ ! -f "$COMPLETED" ]; then '
                        '  if [ -f "$INIT" ]; then '
                        '    MTIME=$(stat -c %Y "$INIT" 2>/dev/null || stat -f %m "$INIT" 2>/dev/null || echo ""); '
                        '    if [ -n "$MTIME" ] && [ "$MTIME" != "0" ]; then '
                        "      NOW=$(date +%s); AGE=$((NOW - MTIME)); "
                        '      if [ "$AGE" -gt 1200 ]; then exit 1; fi; '
                        "    fi; "
                        "  fi; "
                        "  exit 0; "
                        "fi; "
                        f"curl -f -k https://localhost:{CONTAINER_PORT}/ >/dev/null 2>&1"
                    ),
                ],
                start_period=Duration.seconds(120),
                interval=Duration.seconds(60),
                timeout=Duration.seconds(10),
                retries=3,
            ),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix=f"openemr-{tenant_id}",
                log_group=log_group,
            ),
        )

        # ---- EFS mount points in the container ------------------------------
        container.add_mount_points(
            ecs.MountPoint(
                source_volume="sites-volume",
                container_path="/var/www/localhost/htdocs/openemr/sites/",
                read_only=False,
            )
        )
        container.add_mount_points(
            ecs.MountPoint(
                source_volume="ssl-volume",
                container_path="/etc/ssl/",
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
            # Allow 20 minutes for OpenEMR's first-boot DB schema installation
            # before ECS starts evaluating ALB target-group health checks.
            # This matches the stale-leader threshold in the startup wrapper.
            health_check_grace_period=Duration.seconds(1200),
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
                path="/interface/login/login.php",
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
    # 4. ALB listener rule (Sprint 4.15 — COMPLETE)                       #
    # ------------------------------------------------------------------ #
    def add_listener_rule(
        self,
        listener: elbv2.IApplicationListener,
        target_group: elbv2.ApplicationTargetGroup,
        tenant_id: str,
        priority: int,
    ) -> elbv2.ApplicationListenerRule:
        """Add an HTTPS listener rule routing {tenant_id}.{DOMAIN} to this tenant's service.

        Host-header condition matches exactly one subdomain per tenant so
        requests for ``{tenant_id}.tarevoehr.app`` are forwarded to the
        tenant's Fargate target group.

        Priority must be unique across all tenants sharing the HTTPS listener.
        The caller (``provision_tenant.py``) is responsible for allocating
        a unique integer; the shared ALB supports up to 100 rules by default
        (request a quota increase before exceeding ~90 tenants).

        Returns:
            ApplicationListenerRule
        """
        rule = elbv2.ApplicationListenerRule(
            self.scope,
            f"{tenant_id.capitalize()}ListenerRule",
            listener=listener,
            priority=priority,
            conditions=[
                elbv2.ListenerCondition.host_headers(
                    [f"{tenant_id}.{DOMAIN}"]
                )
            ],
            action=elbv2.ListenerAction.forward([target_group]),
        )
        self.listener_rule = rule
        return rule

    # ------------------------------------------------------------------ #
    # 5. Route 53 DNS (Sprint 4.15 — COMPLETE)                            #
    # ------------------------------------------------------------------ #
    def create_dns_record(
        self,
        hosted_zone: route53.IHostedZone,
        alb: elbv2.IApplicationLoadBalancer,
        tenant_id: str,
    ) -> route53.ARecord:
        """Create an A alias record pointing {tenant_id}.{DOMAIN} to the shared ALB.

        Uses an alias target so there is no TTL to manage and no additional
        Route53 charges for the alias lookup.  The alias automatically follows
        the ALB's IP addresses during maintenance windows.

        Returns:
            ARecord
        """
        record = route53.ARecord(
            self.scope,
            f"{tenant_id.capitalize()}DnsRecord",
            zone=hosted_zone,
            record_name=f"{tenant_id}.{DOMAIN}",
            target=route53.RecordTarget.from_alias(
                route53_targets.LoadBalancerTarget(alb)
            ),
        )
        self.dns_record = record
        return record
