import pytest
from fastapi import HTTPException

from app.security_scope import (
    ScopeViolation,
    normalize_scope_entry,
    normalize_target,
    scope_host_allowed,
    scope_path_allowed,
    scope_port_allowed,
    validate_scope_policy,
    validate_target,
    validate_target_against_scope,
)


def test_normalize_target_adds_https_and_removes_trailing_slash():
    assert normalize_target("example.com/") == "https://example.com"


def test_normalize_target_rejects_credentials():
    with pytest.raises(ValueError):
        normalize_target("https://user:password@example.com")


def test_validate_target_rejects_loopback_ip():
    with pytest.raises(HTTPException):
        validate_target("http://127.0.0.1")


def test_validate_target_rejects_local_hostname():
    with pytest.raises(HTTPException):
        validate_target("http://localhost")


def test_scope_policy_can_be_drafted_before_authorization_acknowledgement():
    policy = validate_scope_policy(
        {
            "enabled": False,
            "authorized_targets": ["example.com"],
            "excluded_targets": [],
            "allowed_ports": [443],
            "allowed_paths": ["/"],
            "blocked_paths": [],
            "authorization_acknowledged": False,
        },
        max_concurrency=1,
        max_requests=100,
        max_redirects=2,
    )
    assert policy["authorized_targets"] == ["example.com"]


def test_enabled_scope_requires_authorization_and_target():
    base = {
        "enabled": True,
        "authorized_targets": [],
        "excluded_targets": [],
        "allowed_ports": [443],
        "allowed_paths": ["/"],
        "blocked_paths": [],
        "authorization_acknowledged": False,
    }
    with pytest.raises(ValueError, match="authorized target"):
        validate_scope_policy(base, max_concurrency=1, max_requests=100, max_redirects=2)

    base["authorized_targets"] = ["example.com"]
    with pytest.raises(ValueError, match="acknowledgement"):
        validate_scope_policy(base, max_concurrency=1, max_requests=100, max_redirects=2)


def test_scope_matching_honors_wildcards_and_exclusions():
    scope = {
        "enabled": True,
        "authorization_acknowledged": True,
        "authorized_targets": ["example.com", "*.example.net"],
        "excluded_targets": ["admin.example.net"],
        "allowed_ports": [443],
        "allowed_paths": ["/api", "/"],
        "blocked_paths": ["/api/admin"],
    }
    assert scope_host_allowed("example.com", scope)
    assert scope_host_allowed("api.example.net", scope)
    assert not scope_host_allowed("admin.example.net", scope)
    assert not scope_host_allowed("example.org", scope)
    assert scope_port_allowed(443, scope)
    assert not scope_port_allowed(8443, scope)
    assert scope_path_allowed("/api/users", scope)
    assert not scope_path_allowed("/api/admin/users", scope)


def test_scope_rejects_disabled_or_outside_targets():
    scope = {
        "enabled": False,
        "authorization_acknowledged": True,
        "authorized_targets": ["example.com"],
        "excluded_targets": [],
        "allowed_ports": [443],
        "allowed_paths": ["/"],
        "blocked_paths": [],
    }
    with pytest.raises(ScopeViolation, match="disabled"):
        validate_target_against_scope("https://example.com", scope)

    scope["enabled"] = True
    with pytest.raises(ScopeViolation, match="outside"):
        validate_target_against_scope("https://example.org", scope)


def test_scope_rejects_disallowed_port_and_path():
    scope = {
        "enabled": True,
        "authorization_acknowledged": True,
        "authorized_targets": ["example.com"],
        "excluded_targets": [],
        "allowed_ports": [443],
        "allowed_paths": ["/api"],
        "blocked_paths": ["/api/admin"],
    }
    with pytest.raises(ScopeViolation, match="port"):
        validate_target_against_scope("https://example.com:8443/api", scope)
    with pytest.raises(ScopeViolation, match="blocked"):
        validate_target_against_scope("https://example.com/api/admin", scope)


def test_scope_entry_rejects_private_networks():
    with pytest.raises(ValueError, match="Private"):
        normalize_scope_entry("10.0.0.0/8")
