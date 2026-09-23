from app.auth import Principal, issue_token, principal_from_token
from app.rbac import PERMISSIONS, Role
from app.security_scope import normalize_target


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



def test_password_hash_round_trip():
    from app.security import hash_password, verify_password

    password = "correct-horse-battery-staple"
    assert verify_password(password, hash_password(password))


def test_legacy_sha256_password_is_verifiable():
    import hashlib
    from app.security import is_legacy_sha256, verify_legacy_sha256

    password = "legacy-password"
    stored = hashlib.sha256(password.encode()).hexdigest()
    assert is_legacy_sha256(stored)
    assert verify_legacy_sha256(password, stored)
    assert not verify_legacy_sha256("wrong-password", stored)
