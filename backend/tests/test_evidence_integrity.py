from app.api.findings import FindingUpdate, serialize


def test_finding_update_model_does_not_accept_evidence_mutation():
    payload = FindingUpdate(status="triaged", assignee="analyst")
    assert not hasattr(payload, "evidence")


def test_serialized_finding_exposes_evidence_for_read_only_consumers():
    class FindingStub:
        id = "finding-1"
        scan_id = "scan-1"
        module = "tls"
        title = "Certificate issue"
        severity = "medium"
        status = "open"
        fingerprint = "abc"
        cve = None
        cwe = None
        cvss = None
        assignee = None
        description = "Observed certificate metadata."
        remediation = "Review certificate configuration."
        evidence = {"url": "https://example.com", "status_code": 200}
        confidence = 1.0
        first_seen = None
        last_seen = None

    result = serialize(FindingStub())
    assert result["evidence"] == {"url": "https://example.com", "status_code": 200}
