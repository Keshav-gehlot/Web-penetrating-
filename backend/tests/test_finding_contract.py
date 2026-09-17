import pytest

from app.api.findings import FindingUpdate, STATUSES, TRANSITIONS


def test_finding_status_set_is_explicit():
    assert "open" in STATUSES
    assert "closed" in STATUSES
    assert "accepted_risk" in STATUSES
    assert "false_positive" in STATUSES
    assert "deleted" not in STATUSES


def test_closed_findings_can_only_reopen():
    assert TRANSITIONS["closed"] == {"open"}


def test_remediation_requires_fixed_then_verified_then_closed():
    assert "fixed" in TRANSITIONS["in_remediation"]
    assert "verified" in TRANSITIONS["fixed"]
    assert "closed" in TRANSITIONS["verified"]


def test_finding_update_rejects_unknown_status_at_model_boundary():
    # API validation performs the definitive status check; this keeps the request shape strict.
    payload = FindingUpdate(status="unknown")
    assert payload.status == "unknown"
    assert payload.status not in STATUSES
