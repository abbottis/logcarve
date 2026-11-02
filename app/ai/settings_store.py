"""DB-backed backend AI settings with encrypted per-provider keys (ADR 0004).

Administrative overlay stored in the existing ``admin_settings`` table:

- ``ai.enabled``: ``"0"``/``"1"`` (unset means the operator env default).
- ``ai.provider`` / ``ai.model``: selected provider and its bounded model.
- ``ai.policy.<provider>``: ``"synthetic"`` (explicit synthetic-only
  demo mode) or ``"real"`` (provider-specific explicit real-data policy
  acknowledgment). Unset blocks real data. Acknowledgments never
  transfer across providers: switching provider resolves only the new
  provider's own record.
- ``ai.key.<provider>``: AES-256-GCM ciphertext (base64 nonce plus
  ciphertext) bound to the provider as associated data. Blank input
  keeps the stored key; explicit removal deletes it.
- ``ai.workspace.anthropic``: optional bounded plaintext workspace ID.

Secrets are encrypted at rest with a NEW dedicated server-only
``AI_SETTINGS_KEY`` (never the original-IP/HMAC/session/product
key). Missing, invalid, wrong or tampered keys fail closed with fixed
codes and never break deterministic analytics. Stored keys, suffixes
and validation input are never returned, logged or rendered: callers
learn only configured/not-configured (or env-managed) state.

Key resolution order per provider is stored-ciphertext first, then
the operator env fallback (``MODEL_API_KEY`` for Meta,
``OPENAI_API_KEY`` / ``GEMINI_API_KEY`` / ``ANTHROPIC_API_KEY`` for
the new providers). Removal is honest: deleting the stored key while
an env fallback exists reports ``env-managed`` instead of pretending
the provider is keyless.
"""

import base64
import binascii
import hashlib
import hmac
import os
import re
import sqlite3
from datetime import UTC, datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.ai import catalog

SETTINGS_KEY_ENV = "AI_SETTINGS_KEY"
NONCE_BYTES = 12
KEY_BYTES = 32
AAD_VERSION = b"logcarve-ai-v1"

PROVIDER_ENV_KEYS = {
    "meta": "MODEL_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

WORKSPACE_ENV = "ANTHROPIC_WORKSPACE_ID"

#: Keys that must never serve as the AI settings key (strict separation).
#: Includes every product provider key env var: the settings key must
#: be dedicated, never equal to any provider credential.
_FORBIDDEN_KEY_NAMES = (
    "SESSION_SECRET",
    "HMAC_KEY",
    "ORIGINAL_IP_KEY",
    "MODEL_API_KEY",
    "META_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "ANTHROPIC_API_KEY",
)

POLICY_SYNTHETIC = "synthetic"
POLICY_REAL = "real"
POLICIES = (POLICY_SYNTHETIC, POLICY_REAL)

KEY_SETTING_PREFIX = "ai.key."
POLICY_SETTING_PREFIX = "ai.policy."
ENABLED_SETTING = "ai.enabled"
PROVIDER_SETTING = "ai.provider"
MODEL_SETTING = "ai.model"
WORKSPACE_SETTING = "ai.workspace.anthropic"

#: Bounds for stored settings values (password input for a new key).
KEY_MAX_CHARS = 512
WORKSPACE_MAX_CHARS = 128


class SettingsStoreError(Exception):
    """A safe, fixed-code AI settings failure (never carries secrets)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_HEX_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_B64STD_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_B64URL_RE = re.compile(r"[A-Za-z0-9\-_]*={0,2}\Z")


def _secret_value(value: object) -> object:
    get_secret = getattr(value, "get_secret_value", None)
    if callable(get_secret):
        return get_secret()
    return value


def parse_settings_key(value: object) -> bytes:
    """Parse the dedicated AI settings key; fail closed with fixed codes."""
    if value is None:
        raise SettingsStoreError("key_unavailable", "No AI settings key is configured.")
    raw = _secret_value(value)
    if isinstance(raw, bytes):
        if len(raw) == KEY_BYTES:
            return bytes(raw)
        raise SettingsStoreError("key_invalid", "The AI settings key is invalid.")
    if not isinstance(raw, str):
        raise SettingsStoreError("key_invalid", "The AI settings key is invalid.")
    text = raw.strip("\r\n")
    if not text:
        raise SettingsStoreError("key_unavailable", "No AI settings key is configured.")
    if _HEX_RE.match(text):
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise SettingsStoreError("key_invalid", "The AI settings key is invalid.") from None
    if 43 <= len(text) <= 45 and len(text) % 4 != 1:
        padded = text + "=" * (-len(text) % 4)
        for pattern, altchars in ((_B64STD_RE, None), (_B64URL_RE, b"-_")):
            if pattern.match(padded):
                try:
                    if altchars is None:
                        decoded = base64.b64decode(padded.encode("ascii"), validate=True)
                    else:
                        decoded = base64.b64decode(
                            padded.encode("ascii"), altchars=altchars, validate=True
                        )
                except (binascii.Error, ValueError, UnicodeEncodeError):
                    continue
                if len(decoded) == KEY_BYTES:
                    return decoded
                raise SettingsStoreError("key_invalid", "The AI settings key is invalid.") from None
    raise SettingsStoreError("key_invalid", "The AI settings key is invalid.")


def load_settings_key(explicit: object = None) -> bytes | None:
    """Return the configured AI settings key, or None when absent."""
    if explicit is not None:
        unwrapped = _secret_value(explicit)
        blank = (isinstance(unwrapped, str) and not unwrapped.strip()) or (
            isinstance(unwrapped, bytes) and not unwrapped
        )
        if blank:
            explicit = None
    source = explicit if explicit is not None else os.environ.get(SETTINGS_KEY_ENV)
    if source is None:
        return None
    return parse_settings_key(source)


def require_settings_key(explicit: object = None) -> bytes:
    """Return the configured key; enforce strict separation from other keys."""
    key = load_settings_key(explicit)
    if key is None:
        raise SettingsStoreError("key_unavailable", "No AI settings key is configured.")
    for name in _FORBIDDEN_KEY_NAMES:
        other = os.environ.get(name)
        if not other:
            continue
        try:
            other_key = parse_settings_key(other)
        except SettingsStoreError:
            continue
        if hmac.compare_digest(other_key, key):
            raise SettingsStoreError("key_invalid", "The AI settings key is invalid.")
    return key


def reject_settings_key_reuse(candidate: str, *, key: bytes) -> None:
    """Reject a new provider key that reuses the AI settings key.

    Normalized comparison: a candidate that parses as a settings key
    (hex or base64 32-byte form) and matches the dedicated key bytes
    is rejected with a fixed code. Plain provider credentials that are
    not valid settings-key encodings pass; separation against existing
    env vars is enforced separately by :func:`require_settings_key`.
    """
    if not isinstance(candidate, str) or not candidate:
        return
    try:
        parsed = parse_settings_key(candidate.strip())
    except SettingsStoreError:
        return
    if len(key) == KEY_BYTES and hmac.compare_digest(parsed, key):
        raise SettingsStoreError("key_invalid", "The provider key is invalid.")


def _aad(provider: str) -> bytes:
    return AAD_VERSION + b":" + provider.encode("utf-8")


def encrypt_provider_key(provider: str, plaintext: str, *, key: bytes) -> str:
    """Encrypt one provider key; returns base64 nonce+ciphertext."""
    catalog.validate_pair(provider, catalog.default_model(provider))
    if not isinstance(plaintext, str) or not 1 <= len(plaintext) <= KEY_MAX_CHARS:
        raise SettingsStoreError("key_invalid", "The provider key is invalid.")
    if len(key) != KEY_BYTES:
        raise SettingsStoreError("key_invalid", "The AI settings key is invalid.")
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _aad(provider))
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_provider_key(provider: str, stored: str, *, key: bytes) -> str:
    """Decrypt one stored provider key; fail closed with a fixed code."""
    if len(key) != KEY_BYTES:
        raise SettingsStoreError("decrypt_failed", "The stored provider key is unavailable.")
    try:
        raw = base64.b64decode(stored.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise SettingsStoreError(
            "decrypt_failed", "The stored provider key is unavailable."
        ) from None
    if len(raw) <= NONCE_BYTES:
        raise SettingsStoreError("decrypt_failed", "The stored provider key is unavailable.")
    nonce, ciphertext = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
    try:
        plaintext = AESGCM(bytes(key)).decrypt(nonce, ciphertext, _aad(provider))
    except InvalidTag:
        raise SettingsStoreError(
            "decrypt_failed", "The stored provider key is unavailable."
        ) from None
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise SettingsStoreError(
            "decrypt_failed", "The stored provider key is unavailable."
        ) from None
    if not 1 <= len(text) <= KEY_MAX_CHARS:
        raise SettingsStoreError("decrypt_failed", "The stored provider key is unavailable.")
    return text


def key_fingerprint(secret: str) -> str:
    """In-memory-only binding fingerprint (sha256 hex); never logged/stored."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def get_setting(conn: sqlite3.Connection, key: str) -> str | None:
    """Raw persisted admin setting, or None when never stored."""
    row = conn.execute("SELECT value FROM admin_settings WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row[0])


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Persist one admin setting with an update timestamp."""
    conn.execute(
        "INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value,"
        " updated_at = excluded.updated_at",
        (key, value, datetime.now(UTC).isoformat()),
    )


def delete_setting(conn: sqlite3.Connection, key: str) -> None:
    """Delete one admin setting; absent keys are a no-op."""
    conn.execute("DELETE FROM admin_settings WHERE key = ?", (key,))


def validate_provider_model(provider: str, model: str) -> None:
    """Reject unknown providers and unapproved models before any dispatch."""
    try:
        catalog.validate_pair(provider, model)
    except (KeyError, ValueError) as exc:
        raise SettingsStoreError(
            "unapproved_model", "The selected model is not available."
        ) from exc


def validate_policy(value: str) -> str:
    """Validate a per-provider data-policy selection."""
    if value not in (POLICY_SYNTHETIC, POLICY_REAL):
        raise SettingsStoreError("invalid_policy", "The data-policy selection is invalid.")
    return value
