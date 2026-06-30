"""Unit tests for tenant database name normalization."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

from tarevo.components.tenant_resources import tenant_database_name


def _load_tenant_db_provisioner_module(monkeypatch):
    """Load the tenant DB provisioner module with lightweight dependency stubs."""
    fake_cfnresponse = types.SimpleNamespace(
        SUCCESS="SUCCESS",
        FAILED="FAILED",
        send=lambda *_args, **_kwargs: None,
    )

    class _OperationalError(Exception):
        """Stub pymysql operational error type."""

    fake_pymysql = types.SimpleNamespace(
        connect=lambda **_kwargs: None,
        err=types.SimpleNamespace(OperationalError=_OperationalError),
        Connection=object,
    )
    monkeypatch.setitem(sys.modules, "cfnresponse", fake_cfnresponse)
    monkeypatch.setitem(sys.modules, "pymysql", fake_pymysql)

    module_path = Path(__file__).resolve().parents[2] / "tarevo" / "lambda" / "tenant_db_provisioner" / "index.py"
    spec = importlib.util.spec_from_file_location("tenant_db_provisioner_index", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tenant_database_name_replaces_hyphens_with_underscores():
    """Hyphenated tenant IDs should map to valid MySQL identifiers."""
    assert tenant_database_name("saenz-therapeutic-care") == "saenz_therapeutic_care_db"


def test_tenant_database_name_keeps_safe_identifiers():
    """Already-safe identifiers should only receive the _db suffix."""
    assert tenant_database_name("acme2") == "acme2_db"


def test_provisioner_db_name_matches_tenant_resource_helper(monkeypatch):
    """Provisioner and ECS env wiring must derive the same DB name."""
    module = _load_tenant_db_provisioner_module(monkeypatch)
    tenant_id = "saenz-therapeutic-care"
    assert module._tenant_database_name(tenant_id) == tenant_database_name(tenant_id)
