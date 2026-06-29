#!/usr/bin/env python3
"""CDK application entry point.

Production mode: only SharedInfraStack is instantiated here.
Per-tenant stacks are provisioned on-demand via:

    python scripts/provision_tenant.py --tenant-id <id> --priority <int>

This avoids bundling per-tenant CloudFormation stacks into the shared
infra pipeline and lets each tenant be deployed/destroyed independently.
"""

import os

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks

from tarevo.shared_infra_stack import SharedInfraStack
from tarevo.tenant_stack import TenantStack

app = cdk.App()
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
cdk.Aspects.of(app).add(HIPAASecurityChecks(verbose=True))

env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"),
    region=os.getenv("CDK_DEFAULT_REGION"),
)

# ── Shared infrastructure — one instance per platform region ──────────────────────
# Deploys: KMS key, ACM cert, VPC, ALB, WAF, ECS cluster,
#          tenant registry, provisioner Lambda, ECR repository.
SharedInfraStack(app, "TarevoSharedInfra", env=env)

# ── Sprint 5 Phase B staging verification tenants (removed after testing) ─────
# Note: tenant IDs must not contain hyphens — hyphens are not valid in unquoted
# MySQL identifiers and will cause OpenEMR’s setup scripts to fail.
TenantStack(app, "TarevoTenant-testa", tenant_id="testa", listener_priority=100, env=env)
TenantStack(app, "TarevoTenant-testb", tenant_id="testb", listener_priority=200, env=env)

app.synth()
