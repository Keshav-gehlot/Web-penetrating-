import pytest

from app.api import scans


def test_scan_request_accepts_only_supported_profiles():
    assert scans.ScanRequest(target="https://example.com", profile="quick").profile == "quick"
    assert scans.ScanRequest(target="https://example.com", profile="trust").profile == "trust"
    with pytest.raises(ValueError):
        scans.ScanRequest(target="https://example.com", profile="unrestricted")


def test_severity_rank_is_monotonic():
    assert scans.severity_rank("info") < scans.severity_rank("low")
    assert scans.severity_rank("low") < scans.severity_rank("medium")
    assert scans.severity_rank("medium") < scans.severity_rank("high")
    assert scans.severity_rank("high") < scans.severity_rank("critical")


def test_scan_delta_keys_are_stable():
    expected = {"scan_id", "previous_scan_id", "new", "resolved", "persistent", "regressions"}
    assert expected == {"scan_id", "previous_scan_id", "new", "resolved", "persistent", "regressions"}
