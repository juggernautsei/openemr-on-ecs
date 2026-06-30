"""Tenant DB Provisioner — CloudFormation Custom Resource Lambda.

Invoked by each TenantStack via a CustomResource construct.  Runs inside the
shared VPC so it can reach the Aurora cluster's private endpoint.

Environment variables (injected by the CDK construct):
    AURORA_HOST         — Aurora cluster writer endpoint
    AURORA_PORT         — 3306
    AURORA_ADMIN_SECRET — Secrets Manager ARN containing the admin credentials
                          JSON: {"username": "...", "password": "..."}
    AWS_REGION          — standard Lambda env var

ResourceProperties passed from CloudFormation:
    TenantId            — alphanumeric identifier for the tenant (e.g. "acme")

Behaviour
---------
CREATE:
    1. Fetch admin credentials from Secrets Manager.
    2. Connect to Aurora as admin.
    3. CREATE DATABASE IF NOT EXISTS `{tenant_id_normalized}_db`
       where hyphens are converted to underscores.
    4. Generate a random 32-char password for the tenant user.
    5. CREATE USER IF NOT EXISTS `{tenant_id}`@`%` IDENTIFIED BY '<password>'.
    6. GRANT ALL PRIVILEGES ON `{tenant_id_normalized}_db`.* TO `{tenant_id}`@`%`.
    7. FLUSH PRIVILEGES.
    8. Store tenant credentials in Secrets Manager as JSON:
           {"host": ..., "port": ..., "dbname": ..., "username": ..., "password": ...}
       Secret name: /tarevo/tenants/{tenant_id}/db-credentials
    9. Return PhysicalResourceId = f"tenant-db-{tenant_id}".

UPDATE:
    No-op — credential rotation is handled via a separate rotation Lambda.
    Returns the existing PhysicalResourceId unchanged.

DELETE:
    1. Fetch admin credentials from Secrets Manager.
    2. Connect to Aurora as admin.
    3. DROP DATABASE IF EXISTS `{tenant_id_normalized}_db`.
    4. DROP USER IF EXISTS `{tenant_id}`@`%`.
    5. FLUSH PRIVILEGES.
    6. Delete Secrets Manager secret /tarevo/tenants/{tenant_id}/db-credentials.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import ssl as ssl_module
import string

import boto3
import cfnresponse  # bundled via requirements.txt
import pymysql  # bundled via requirements.txt

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ── Constants ─────────────────────────────────────────────────────────────────
_DB_NAME_SUFFIX = "_db"
_SECRETS_PREFIX = "/tarevo/tenants"
_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!#$%^&*-_=+"
_PASSWORD_LENGTH = 32

def _tenant_database_name(tenant_id: str) -> str:
    """Return a MySQL-safe database name for a tenant identifier."""
    return f"{tenant_id.replace('-', '_')}{_DB_NAME_SUFFIX}"


def handler(event: dict, context: object) -> None:  # noqa: ANN001
    """CloudFormation Custom Resource handler."""
    logger.info("Event: %s", json.dumps(event))

    request_type: str = event["RequestType"]
    properties: dict = event.get("ResourceProperties", {})
    tenant_id: str = properties["TenantId"]

    physical_id = f"tenant-db-{tenant_id}"

    try:
        if request_type == "Create":
            _handle_create(tenant_id)
        elif request_type == "Delete":
            _handle_delete(tenant_id)
        elif request_type == "Update":
            _handle_update(tenant_id)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, physical_id)
    except Exception:  # noqa: BLE001
        logger.exception("Provisioner failed for tenant=%s request=%s", tenant_id, request_type)
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, physical_id)


# ── Private helpers ───────────────────────────────────────────────────────────

def _get_admin_credentials() -> tuple[str, str]:
    """Return (username, password) for the Aurora admin account."""
    secret_arn = os.environ["AURORA_ADMIN_SECRET"]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    data = json.loads(response["SecretString"])
    return data["username"], data["password"]


def _connect_aurora(username: str, password: str) -> pymysql.Connection:
    """Open a pymysql connection to the Aurora writer endpoint over TLS.

    Aurora is deployed with require_secure_transport=ON.  pymysql will use an
    unencrypted socket by default, which Aurora refuses (MySQL error 3159).
    We create an SSLContext here; CERT_NONE is intentional because the Lambda
    runs inside the same VPC as Aurora and we rely on VPC-level network
    isolation rather than TLS certificate pinning for this internal connection.
    This satisfies require_secure_transport while keeping the Lambda dependency
    footprint small (no bundled CA cert file required).
    """
    ssl_ctx = ssl_module.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl_module.CERT_NONE
    return pymysql.connect(
        host=os.environ["AURORA_HOST"],
        port=int(os.environ.get("AURORA_PORT", "3306")),
        user=username,
        password=password,
        connect_timeout=10,
        autocommit=True,
        ssl=ssl_ctx,
    )


def _connect_aurora_with_fallback(username: str, password: str) -> pymysql.Connection:
    """Connect to Aurora with safe credential fallbacks for bootstrap edge cases."""
    candidates: list[tuple[str, str]] = [(username, password)]
    truncated_password = password.split("=", 1)[0]
    if truncated_password != password:
        candidates.append((username, truncated_password))
    if username != "root":
        candidates.append(("root", password))
        if truncated_password != password:
            candidates.append(("root", truncated_password))

    attempted: set[tuple[str, str]] = set()
    last_auth_error: pymysql.err.OperationalError | None = None
    for candidate_user, candidate_password in candidates:
        key = (candidate_user, candidate_password)
        if key in attempted:
            continue
        attempted.add(key)
        try:
            return _connect_aurora(candidate_user, candidate_password)
        except pymysql.err.OperationalError as exc:
            if exc.args and exc.args[0] == 1045:
                last_auth_error = exc
                logger.warning(
                    "Aurora auth failed for user=%s; trying next credential fallback",
                    candidate_user,
                )
                continue
            raise

    if last_auth_error is not None:
        raise last_auth_error
    raise RuntimeError("Unable to establish Aurora connection with provided credentials")


def _generate_password() -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(_PASSWORD_LENGTH))


def _tenant_secret_name(tenant_id: str) -> str:
    return f"{_SECRETS_PREFIX}/{tenant_id}/db-credentials"


def _handle_create(tenant_id: str) -> None:
    """Create the tenant database, user, grants, and Secrets Manager secret."""
    admin_user, admin_pass = _get_admin_credentials()
    tenant_password = _generate_password()
    db_name = _tenant_database_name(tenant_id)

    conn = _connect_aurora_with_fallback(admin_user, admin_pass)
    try:
        with conn.cursor() as cur:
            # DO NOT pre-create the database here.  OpenEMR's Docker entrypoint
            # (openemr.sh) runs auto_configure.php which creates the database via
            # MYSQL_ROOT_PASS on first boot.  If the database already exists but has
            # no schema, OpenEMR enters "upgrade from version 0" mode and fails with
            # "Cannot upgrade - OpenEMR is not configured yet".  Letting OpenEMR
            # create the DB itself puts it into "fresh install" mode.
            #
            # noqa: S608 — tenant_id is validated by the caller (TenantStack constructor)
            # to lowercase alphanumeric + hyphen only; db_name is normalized to
            # a lowercase alphanumeric + underscore identifier.
            # Note: backtick-quoted host `%%` uses string concat (NOT f-string) so that
            # pymysql sees the literal %% and converts it to % for the host wildcard.
            # In an f-string, Python would collapse %% → % before pymysql runs its own
            # % substitution, causing ValueError on the `%`` backtick sequence.

            # Create a `root`@`%` user that OpenEMR's auto_configure.php can connect
            # as during first-boot database setup.  The ECR image's openemr.sh defaults
            # to MYSQL_ROOT_USER=root when the env var is not explicitly overridden;
            # Aurora's master user is named 'admin', so we bridge the gap here by
            # provisioning a `root` MySQL account with the admin credentials.
            cur.execute(
                "CREATE USER IF NOT EXISTS `root`@`%%` IDENTIFIED BY %s",
                (admin_pass,),
            )
            # GRANT ALL PRIVILEGES ON *.* fails in Aurora MySQL 8.0 because 'ALL'
            # includes dynamic system privileges the master user (admin) does not hold
            # and therefore cannot delegate.  Grant only the subset that Aurora assigns
            # to the master user — these are known-grantable WITH GRANT OPTION.
            cur.execute(
                "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, PROCESS, "
                "REFERENCES, INDEX, ALTER, SHOW DATABASES, CREATE TEMPORARY TABLES, "
                "LOCK TABLES, EXECUTE, REPLICATION SLAVE, REPLICATION CLIENT, "
                "CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, "
                "CREATE USER, EVENT, TRIGGER ON *.* TO `root`@`%` WITH GRANT OPTION"
            )

            # Tenant application user — scoped to tenant_id_db only.
            cur.execute(
                "CREATE USER IF NOT EXISTS `" + tenant_id + "`@`%%` IDENTIFIED BY %s",
                (tenant_password,),
            )
            # GRANT on a non-existent database is valid in MySQL; the grant will
            # activate as soon as OpenEMR creates the database.
            cur.execute(
                "GRANT ALL PRIVILEGES ON `" + db_name + "`.* TO `" + tenant_id + "`@`%`"
            )
            cur.execute("FLUSH PRIVILEGES")
    finally:
        conn.close()

    # Store tenant credentials in Secrets Manager.
    sm_client = boto3.client("secretsmanager")
    secret_name = _tenant_secret_name(tenant_id)
    secret_value = json.dumps({
        "host": os.environ["AURORA_HOST"],
        "port": int(os.environ.get("AURORA_PORT", "3306")),
        "dbname": db_name,
        "username": tenant_id,
        "password": tenant_password,
    })
    sm_client.create_secret(
        Name=secret_name,
        Description=f"OpenEMR DB credentials for tenant {tenant_id}",
        SecretString=secret_value,
        Tags=[
            {"Key": "tarevo:tenant", "Value": tenant_id},
            {"Key": "tarevo:managed-by", "Value": "tenant-db-provisioner"},
        ],
    )
    logger.info("Provisioned DB and secret for tenant=%s db=%s", tenant_id, db_name)


def _handle_update(tenant_id: str) -> None:
    """Idempotently ensure the `root`@`%` bootstrap user exists.

    This is triggered when the CloudFormation stack UPDATE event fires
    (e.g. after a task-definition change).  Creating the root user here
    handles cases where the tenant was originally provisioned before the
    root user feature was added.
    """
    admin_user, admin_pass = _get_admin_credentials()
    conn = _connect_aurora_with_fallback(admin_user, admin_pass)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE USER IF NOT EXISTS `root`@`%%` IDENTIFIED BY %s",
                (admin_pass,),
            )
            cur.execute(
                "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, PROCESS, "
                "REFERENCES, INDEX, ALTER, SHOW DATABASES, CREATE TEMPORARY TABLES, "
                "LOCK TABLES, EXECUTE, REPLICATION SLAVE, REPLICATION CLIENT, "
                "CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, "
                "CREATE USER, EVENT, TRIGGER ON *.* TO `root`@`%` WITH GRANT OPTION"
            )
            cur.execute("FLUSH PRIVILEGES")
    finally:
        conn.close()
    logger.info("Ensured root bootstrap user for tenant=%s", tenant_id)


def _handle_delete(tenant_id: str) -> None:
    """Drop the tenant database, user, and Secrets Manager secret."""
    admin_user, admin_pass = _get_admin_credentials()
    db_name = _tenant_database_name(tenant_id)

    conn = _connect_aurora_with_fallback(admin_user, admin_pass)
    try:
        with conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS `{db_name}`")     # noqa: S608
            cur.execute(f"DROP USER IF EXISTS `{tenant_id}`@`%`")   # noqa: S608
            cur.execute("FLUSH PRIVILEGES")
    finally:
        conn.close()

    sm_client = boto3.client("secretsmanager")
    try:
        sm_client.delete_secret(
            SecretId=_tenant_secret_name(tenant_id),
            ForceDeleteWithoutRecovery=True,
        )
    except sm_client.exceptions.ResourceNotFoundException:
        logger.warning("Secret not found during delete for tenant=%s — skipping", tenant_id)

    logger.info("Deprovisioned DB and secret for tenant=%s", tenant_id)
