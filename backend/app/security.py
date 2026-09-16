from __future__ import annotations
import base64, hashlib, hmac, secrets
ITERATIONS = 310_000
PREFIX = "pbkdf2_sha256"

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"{PREFIX}${ITERATIONS}${base64.urlsafe_b64encode(salt).decode().rstrip('=')}${digest.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        prefix, rounds, salt_text, expected = stored.split("$", 3)
        if prefix != PREFIX: return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False

def is_legacy_sha256(stored: str) -> bool:
    return len(stored) == 64 and all(c in "0123456789abcdef" for c in stored.lower())

def verify_legacy_sha256(password: str, stored: str) -> bool:
    return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)
