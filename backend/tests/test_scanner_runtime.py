import pytest
from app.scanners.runtime import ScanAuth, configure_runtime, ensure_runtime, _assert_public_host, _request_headers
from app.config import settings

def test_runtime_is_scoped_by_scan_id():
    first = ensure_runtime("scan-a")
    first.requests = 3
    assert ensure_runtime("scan-a") is first
    second = ensure_runtime("scan-b")
    assert second is not first
    assert second.requests == 0

def test_scan_request_budget_is_positive():
    assert settings.SCAN_REQUEST_BUDGET > 0
    assert settings.SCAN_MAX_REDIRECTS >= 0
    assert settings.SCAN_MAX_RESPONSE_BYTES >= 65536

def test_runtime_rejects_unspecified_destination():
    with pytest.raises(RuntimeError):
        _assert_public_host("http://0.0.0.0/")


def test_bearer_auth_header_is_runtime_scoped():
    configure_runtime("auth-scan", auth=ScanAuth(kind="bearer", secret="token-123"))
    headers = _request_headers()
    assert headers["Authorization"] == "Bearer token-123"
    assert headers["User-Agent"].startswith("PHANTOM/2.0")

def test_basic_auth_header_is_runtime_scoped():
    configure_runtime("basic-scan", auth=ScanAuth(kind="basic", username="alice", secret="password"))
    headers = _request_headers()
    assert headers["Authorization"].startswith("Basic ")
    assert "password" not in headers["User-Agent"]

def test_api_key_header_is_runtime_scoped():
    configure_runtime("api-key-scan", auth=ScanAuth(kind="api_key", secret="secret", header_name="X-Test-Key"))
    headers = _request_headers()
    assert headers["X-Test-Key"] == "secret"
