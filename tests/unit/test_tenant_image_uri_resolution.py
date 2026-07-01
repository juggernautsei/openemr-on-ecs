"""Unit tests for tenant image URI resolution behavior."""

from __future__ import annotations

import pytest

from tarevo.components.tenant_resources import ECR_IMAGE_URI, resolve_tenant_image_uri


def test_resolve_tenant_image_uri_uses_default_when_override_missing():
    """Missing tenant override should use the shared default image URI."""
    assert resolve_tenant_image_uri(None) == ECR_IMAGE_URI


def test_resolve_tenant_image_uri_uses_trimmed_override():
    """Provided tenant override should be used after trimming whitespace."""
    override = "600430252128.dkr.ecr.us-east-2.amazonaws.com/tarevo-openemr:saenz-custom"
    assert resolve_tenant_image_uri(f"  {override}  ") == override


def test_resolve_tenant_image_uri_rejects_blank_override():
    """Blank tenant override should raise a validation error."""
    with pytest.raises(ValueError, match="tenant_image_uri must be a non-empty image URI"):
        resolve_tenant_image_uri("   ")
