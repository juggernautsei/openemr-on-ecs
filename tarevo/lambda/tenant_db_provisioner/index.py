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
    3. CREATE DATABASE IF NOT EXISTS `{tenant_id}_db`.
    4. Generate a random 32-char password for the tenant user.
    5. CREATE USER IF NOT EXISTS `{tenant_id}`@`%` IDENTIFIED BY '<password>'.
    6. GRANT ALL PRIVILEGES ON `{tenant_id}_db`.* TO `{tenant_id}`@`%`.
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
    3. DROP DATABASE IF EXISTS `{tenant_id}_db`.
    4. DROP USER IF EXISTS `{tenant_id}`@`%`.
    5. FLUSH PRIVILEGES.
    6. Delete Secrets Manager secret /tarevo/tenants/{tenant_id}/db-credentials.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
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
        # UPDATE is intentionally a no-op
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
    """Open a pymysql connection to the Aurora writer endpoint."""
    return pymysql.connect(
        host=os.environ["AURORA_HOST"],
        port=int(os.environ.get("AURORA_PORT", "3306")),
        user=username,
        password=password,
        connect_timeout=10,
        autocommit=True,
    )


def _generate_password() -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(_PASSWORD_LENGTH))


def _tenant_secret_name(tenant_id: str) -> str:
    return f"{_SECRETS_PREFIX}/{tenant_id}/db-credentials"


def _handle_create(tenant_id: str) -> None:
    """Create the tenant database, user, grants, and Secrets Manager secret."""
    admin_user, admin_pass = _get_admin_credentials()
    tenant_password = _generate_password()
    db_name = f"{tenant_id}{_DB_NAME_SUFFIX}"

    conn = _connect_aurora(admin_user, admin_pass)
    try:
        with conn.cursor() as cur:
            # Use backtick-quoted identifiers; tenant_id validated downstream.
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")  # noqa: S608
            cur.execute(
                f"CREATE USER IF NOT EXISTS `{tenant_id}`@`%` "  # noqa: S608
                f"IDENTIFIED BY %s",
                (tenant_password,),
            )
            cur.execute(
                f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO `{tenant_id}`@`%`"  # noqa: S608
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


def _handle_delete(tenant_id: str) -> None:
    """Drop the tenant database, user, and Secrets Manager secret."""
    admin_user, admin_pass = _get_admin_credentials()
    db_name = f"{tenant_id}{_DB_NAME_SUFFIX}"

    conn = _connect_aurora(admin_user, admin_pass)
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
