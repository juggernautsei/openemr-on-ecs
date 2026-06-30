#!/usr/bin/env python3
"""CDK application entry point.

Production mode: only SharedInfraStack is instantiated by default.
Per-tenant stacks are provisioned on-demand by passing CDK context:

    cdk deploy TarevoTenant-<tenant> -c tenant_id=<tenant> -c listener_priority=<int>

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
# ── Dynamic tenant stack (optional) ───────────────────────────────────────────────
# When tenant context is provided, synth/deploy only that tenant stack in addition
# to shared infra. This enables on-demand tenant provisioning from CLI scripts.
tenant_id = app.node.try_get_context("tenant_id")
listener_priority_context = app.node.try_get_context("listener_priority")

if tenant_id:
    if listener_priority_context is None:
        raise ValueError(
            "listener_priority context is required when tenant_id is provided. "
            "Use -c listener_priority=<int>."
        )
    try:
        listener_priority = int(listener_priority_context)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "listener_priority must be an integer."
        ) from error

    TenantStack(
        app,
        f"TarevoTenant-{tenant_id}",
        tenant_id=tenant_id,
        listener_priority=listener_priority,
        env=env,
    )

app.synth()
