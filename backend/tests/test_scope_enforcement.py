import pytest
from fastapi import HTTPException

from app.api.scans import ScanRequest, create_scan
from app.auth import Principal
from app.scanners.runtime import (
    _CURRENT,
    bounded_get,
    bounded_resolve,
    ensure_runtime,
    scoped_tcp_socket,
)


@pytest.fixture
def enabled_scope():
    return {
        "id": "scope-1",
        "enabled": True,
        "authorization_acknowledged": True,
        "authorized_targets": ["example.com", "*.example.net"],
        "excluded_targets": ["admin.example.net"],
        "allowed_ports": [443],
        "allowed_paths": ["/api", "/"],
        "blocked_paths": ["/api/admin"],
        "max_requests": 50,
        "max_concurrency": 2,
        "max_redirects": 2,
    }


def test_runtime_rejects_out_of_scope_dns(enabled_scope):
    token = _CURRENT.set(ensure_runtime("scope-1", enabled_scope))
    try:
        with pytest.raises(RuntimeError, match="outside.*scope"):
            bounded_resolve("example.org")
    finally:
        _CURRENT.reset(token)


def test_runtime_rejects_disallowed_tcp_port(enabled_scope):
    token = _CURRENT.set(ensure_runtime("scope-1", enabled_scope))
    try:
        with pytest.raises(RuntimeError, match="port 8443"):
            scoped_tcp_socket("example.com", 8443)
    finally:
        _CURRENT.reset(token)


@pytest.mark.asyncio
async def test_runtime_rejects_out_of_scope_http_path(enabled_scope):
    token = _CURRENT.set(ensure_runtime("scope-1", enabled_scope))
    try:
        with pytest.raises(RuntimeError, match="path is blocked"):
            await bounded_get("https://example.com", "/api/admin/users")
    finally:
        _CURRENT.reset(token)


@pytest.mark.asyncio
async def test_runtime_redirect_recheck_blocks_scope_escape(enabled_scope, monkeypatch):
    import app.scanners.runtime as runtime

    class Response:
        status_code = 302
        headers = {"location": "https://example.org/"}
        content = b""
        url = "https://example.com/"

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url):
            assert url == "https://example.com/"
            return Response()

    monkeypatch.setattr(runtime.httpx, "AsyncClient", lambda **kwargs: Client())
    monkeypatch.setattr(runtime, "_assert_public_host", lambda url: None)
    token = _CURRENT.set(ensure_runtime("scope-1", enabled_scope))
    try:
        with pytest.raises(RuntimeError, match="outside.*scope"):
            await runtime.bounded_snapshot("https://example.com/")
    finally:
        _CURRENT.reset(token)


class FakeDB:
    def __init__(self, scope):
        self.scope = scope

    async def scalar(self, _query):
        return self.scope


@pytest.mark.asyncio
async def test_create_scan_endpoint_rejects_target_outside_scope(monkeypatch, enabled_scope):
    db = FakeDB(enabled_scope)
    principal = Principal("analyst@example.com", "ANALYST", "workspace-1", "user-1")
    monkeypatch.setattr("app.api.scans.record_audit", _noop)
    with pytest.raises(HTTPException) as exc:
        await create_scan(
            ScanRequest(target="https://example.org", profile="quick"),
            None,
            principal,
            db,
        )
    assert exc.value.status_code == 403
    assert "outside" in str(exc.value.detail).lower()


@pytest.mark.asyncio
async def test_create_scan_endpoint_rejects_disabled_scope(monkeypatch):
    db = FakeDB({
        "id": "scope-1",
        "enabled": False,
        "authorization_acknowledged": True,
        "authorized_targets": ["example.com"],
        "excluded_targets": [],
        "allowed_ports": [443],
        "allowed_paths": ["/"],
        "blocked_paths": [],
    })
    principal = Principal("analyst@example.com", "ANALYST", "workspace-1", "user-1")
    monkeypatch.setattr("app.api.scans.record_audit", _noop)
    with pytest.raises(HTTPException) as exc:
        await create_scan(
            ScanRequest(target="https://example.com", profile="quick"),
            None,
            principal,
            db,
        )
    assert exc.value.status_code == 403
    assert "disabled" in str(exc.value.detail).lower()


async def _noop(*args, **kwargs):
    return None
