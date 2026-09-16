from app.auth import Principal, issue_token, principal_from_token


def test_signed_session_round_trip():
    token = issue_token("analyst@example.com", "analyst", "default", "user-1", hours=1)
    principal = principal_from_token(token)
    assert principal == Principal("analyst@example.com", "analyst", "default", "user-1")


def test_tampered_session_is_rejected():
    token = issue_token("analyst@example.com", "analyst", "default", "user-1", hours=1)
    payload, _signature = token.rsplit("|", 1)
    tampered = payload.replace("analyst", "owner", 1) + "|bad"
    try:
        principal_from_token(tampered)
    except Exception:
        return
    raise AssertionError("tampered token was accepted")
