import pytest
from app.scanners.runtime import ensure_runtime, _assert_public_host
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
