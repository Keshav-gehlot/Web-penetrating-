from app.auth import Principal, issue_token, principal_from_token
from app.main import normalize_target
from app.rbac import PERMISSIONS, Role


def test_token_round_trip():
    token = issue_token("tester@example.com", "analyst", "default", "u-1", hours=1)
    principal = principal_from_token(token)
    assert principal == Principal("tester@example.com", "analyst", "default", "u-1")


def test_target_normalization():
    assert normalize_target("example.com") == "https://example.com"
    assert normalize_target("https://example.com/") == "https://example.com"


def test_rbac_permissions_are_server_side():
    assert "scan:create" in PERMISSIONS[Role.ANALYST]
    assert "scan:cancel" not in PERMISSIONS[Role.ANALYST]
    assert "*" in PERMISSIONS[Role.OWNER]


def test_credential_encryption_round_trip(monkeypatch):
    from cryptography.fernet import Fernet
    from app import security
    monkeypatch.setattr(security.settings, "CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    ciphertext = security.encrypt_credential("super-secret-value")
    assert ciphertext != "super-secret-value"
    assert security.decrypt_credential(ciphertext) == "super-secret-value"


def test_credential_encryption_requires_key(monkeypatch):
    from app import security
    monkeypatch.setattr(security.settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    try:
        security.encrypt_credential("secret")
    except RuntimeError as exc:
        assert "not configured" in str(exc)
        return
    raise AssertionError("credential encryption accepted an unset key")
