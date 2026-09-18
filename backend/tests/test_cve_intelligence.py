from app.intelligence.cve import fingerprint_from_header, version_in_range


def test_version_range_matching():
    assert version_in_range("1.24.0", end_excluding="1.25.0")
    assert not version_in_range("1.25.0", end_excluding="1.25.0")
    assert version_in_range("2.0.5", start_including="2.0.0", end_excluding="2.1.0")


def test_exact_version_fingerprint_to_cpe():
    result = fingerprint_from_header("server", "nginx/1.24.0")
    assert result is not None
    assert result["vendor"] == "f5"
    assert result["version"] == "1.24.0"
    assert result["cpe"] == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"


def test_unversioned_fingerprint_does_not_invent_cpe():
    result = fingerprint_from_header("server", "nginx")
    assert result is not None
    assert result["version"] is None
    assert result["cpe"] is None


def test_versioned_cpe_shape_is_deterministic():
    result = fingerprint_from_header("x-powered-by", "PHP/8.2.12")
    assert result["cpe"] == "cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*"


def test_fingerprint_does_not_guess_unknown_product():
    assert fingerprint_from_header("server", "AcmeGateway/9.2.1") is None
