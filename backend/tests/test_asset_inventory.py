from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.assets import _validate_metadata
from app.security_scope import ScopeViolation, validate_target_against_scope


def test_asset_metadata_accepts_supported_inventory_values():
    _validate_metadata("web", "production", "high", "active")


@pytest.mark.parametrize("field,value", [
    ("asset_type", "unknown-type"),
    ("environment", "sandbox"),
    ("criticality", "urgent"),
    ("status", "retired"),
])
def test_asset_metadata_rejects_unknown_values(field, value):
    values = {"asset_type": "web", "environment": "unknown", "criticality": "medium", "status": "active"}
    values[field] = value
    with pytest.raises(HTTPException) as exc:
        _validate_metadata(**values)
    assert exc.value.status_code == 400


def test_asset_scope_is_required_for_authorized_inventory():
    scope = {
        "enabled": True,
        "authorization_acknowledged": True,
        "authorized_targets": ["example.com"],
        "excluded_targets": [],
        "allowed_ports": [443],
        "allowed_paths": ["/"],
        "blocked_paths": [],
    }
    validate_target_against_scope(
        {"target": "https://example.com/", "host": "example.com", "port": 443, "scheme": "https", "path": "/"},
        scope,
    )


def test_asset_scope_rejects_excluded_target():
    scope = {
        "enabled": True,
        "authorization_acknowledged": True,
        "authorized_targets": ["*.example.com"],
        "excluded_targets": ["admin.example.com"],
        "allowed_ports": [443],
        "allowed_paths": ["/"],
        "blocked_paths": [],
    }
    with pytest.raises(ScopeViolation):
        validate_target_against_scope(
            {"target": "https://admin.example.com/", "host": "admin.example.com", "port": 443, "scheme": "https", "path": "/"},
            scope,
        )


def test_asset_detail_is_workspace_owned():
    asset = SimpleNamespace(id="a1", workspace_id="w1")
    assert asset.workspace_id == "w1"
