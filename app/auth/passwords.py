"""Argon2id password hashing for local admin accounts (T5).

Verification failures (wrong password or malformed hash) report False
without distinguishing the cause, so login errors stay non-enumerating.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password with Argon2id; empty passwords are refused."""
    if not password:
        raise ValueError("password must be non-empty")
    return _hasher.hash(password)


def verify_password(encoded_hash: str, password: str) -> bool:
    """Return True on match, False on any verification failure."""
    try:
        return _hasher.verify(encoded_hash, password)
    except (VerificationError, InvalidHashError):
        return False
