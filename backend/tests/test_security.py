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
