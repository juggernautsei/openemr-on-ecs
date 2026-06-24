#!/usr/bin/env python3
"""CDK application entry point — Sprint 4 production branch: sprint/4-shared-infra-refactor.

Production mode: only SharedInfraStack is instantiated here.
Per-tenant stacks are provisioned on-demand via:

    python scripts/provision_tenant.py --tenant-id <id> --priority <int>

This avoids bundling per-tenant CloudFormation stacks into the shared
infra pipeline and lets each tenant be deployed/destroyed independently.

Sprint 4.12 – 4.16 NOTE:
    A synthetic ``TarevoTenant-synth-test`` instance is registered below to
    validate TenantStack nag rules during ``cdk synth``.  It is NOT deployed
    and will be removed once the full TenantStack is validated (after Sprint 4.16).
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

# ── Synth-test TenantStack — validates TenantStack nag rules (Sprints 4.12–16) ──
# NOT deployed.  Removed after Sprint 4.16 validation is complete.
TenantStack(app, "TarevoTenant-synth-test",
            tenant_id="synth-test",
            listener_priority=999,
            env=env)

app.synth()
