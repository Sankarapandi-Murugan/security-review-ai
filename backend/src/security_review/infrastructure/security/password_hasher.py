"""Password hashing using PBKDF2-HMAC-SHA256 (stdlib only, no native extensions required)."""

import hashlib
import hmac
import os

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 390_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_ALGORITHM}${_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_str, salt_hex, hash_hex = encoded.split("$", 3)
    except ValueError:
        return False

    if algorithm != _ALGORITHM:
        return False

    iterations = int(iterations_str)
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived, expected)


def hash_token(raw_token: str) -> str:
    """Deterministic (unsalted) SHA-256 hash for high-entropy random tokens (e.g.
    password-reset tokens generated via ``secrets.token_urlsafe``).

    Unlike ``hash_password``, this must be deterministic so the hash can be looked
    up directly by equality (``WHERE token_hash = ?``) without iterating every row.
    This is safe specifically because the input already has ~256 bits of server-
    generated entropy — never use this for user-supplied secrets like passwords.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_token(raw_token: str, token_hash: str) -> bool:
    return hmac.compare_digest(hash_token(raw_token), token_hash)
