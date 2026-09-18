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


def test_session_bound_token_round_trip():
    from app.auth import issue_token
    token = issue_token("analyst@example.com", "analyst", "default", "user-1", hours=1, session_id="session-1")
    assert principal_from_token(token).session_id == "session-1"


def test_totp_round_trip():
    from app.auth import new_totp_secret, verify_totp
    import base64, hashlib, hmac, struct, time
    secret = new_totp_secret()
    raw = base64.b32decode(secret + "=" * ((8-len(secret)%8)%8), casefold=True)
    counter = int(time.time() // 30)
    digest = hmac.new(raw, struct.pack(">Q", counter), hashlib.sha1).digest()
    pos = digest[-1] & 15
    otp = (struct.unpack(">I", digest[pos:pos+4])[0] & 0x7fffffff) % 1000000
    assert verify_totp(secret, f"{otp:06d}")
