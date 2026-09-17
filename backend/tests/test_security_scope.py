import pytest
from fastapi import HTTPException

from app.security_scope import normalize_target, validate_target


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
