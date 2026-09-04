"""Password hashing with PBKDF2-HMAC-SHA256 (stdlib only)."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from .config import settings


def hash_password(password: str, salt: bytes | None = None,
                  rounds: int | None = None) -> str:
    r = rounds or settings.pbkdf2_rounds
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, r
    )
    return f"pbkdf2_sha256${r}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        alg, r, salt_hex, dk_hex = stored.split("$")
        if alg != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(r)
        )
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


def generate_record_id() -> str:
    return secrets.token_urlsafe(32)