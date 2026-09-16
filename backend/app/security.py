from __future__ import annotations
import hashlib, hmac

def hash_password(password: str) -> str:
    # PBKDF2 is available in Python's standard library; no extra password package required.
    salt = hashlib.sha256(b"phantom-password-salt-v1").digest()
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000).hex()

def verify_password(password: str, stored: str) -> bool:
    # Accept only PHANTOM PBKDF2 hashes for persistent accounts.
    return hmac.compare_digest(hash_password(password), stored)
