from app.api.findings import FindingUpdate, evidence_digest, serialize


def test_finding_update_model_does_not_accept_evidence_mutation():
    payload = FindingUpdate(status="triaged", assignee="analyst")
    assert not hasattr(payload, "evidence")


def test_evidence_digest_is_canonical_and_stable():
    first = {"url": "https://example.com", "status_code": 200, "headers": {"server": "example"}}
    reordered = {"headers": {"server": "example"}, "status_code": 200, "url": "https://example.com"}
    assert evidence_digest(first) == evidence_digest(reordered)
    assert len(evidence_digest(first)) == 64


def test_serialized_finding_exposes_read_only_evidence_provenance():
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
        evidence_hash = evidence_digest(evidence)
        evidence_collected_at = None
        evidence_source = "scanner"
        confidence = 1.0
        first_seen = None
        last_seen = None

    result = serialize(FindingStub())
    assert result["evidence"] == {"url": "https://example.com", "status_code": 200}
    assert result["evidence_hash"] == evidence_digest(FindingStub.evidence)
    assert result["evidence_source"] == "scanner"
