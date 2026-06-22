#!/usr/bin/env python3
"""CDK application entry point — Sprint 3 PoC branch: poc/l2-shared-alb.

This branch is THROWAWAY.  It proves shared-ALB + host-header routing with
L2 constructs before the Sprint 4 full production refactor.

Stacks:
  TarevoSharedInfra  — VPC, wildcard ACM cert, shared ALB/listener, ECS cluster
  TarevoTenant-test-a — nginx stub service, listener rule host=test-a.tarevoehr.app
  TarevoTenant-test-b — nginx stub service, listener rule host=test-b.tarevoehr.app
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

# ── Shared infrastructure (one per platform) ──────────────────────────────────
shared = SharedInfraStack(app, "TarevoSharedInfra", env=env)

# ── Tenant A ──────────────────────────────────────────────────────────────────
TenantStack(
    app,
    "TarevoTenant-test-a",
    shared=shared,
    tenant_id="test-a",
    listener_priority=100,
    env=env,
)

# ── Tenant B ──────────────────────────────────────────────────────────────────
TenantStack(
    app,
    "TarevoTenant-test-b",
    shared=shared,
    tenant_id="test-b",
    listener_priority=200,
    env=env,
)

app.synth()
