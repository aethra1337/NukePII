"""Reversible tokenization vault — Faz-2.

SQLite-backed, AES-GCM concept with stdlib fallback (XOR+HMAC demo is NOT
production crypto; production path requires `cryptography` package).
Local-first: vault file stays on disk, keys via env NUKEPII_VAULT_KEY.

Schema: tokens(token TEXT PK, ciphertext TEXT, pii_type TEXT, created_at TEXT)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

_VAULT_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens(
  token TEXT PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  pii_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


def _get_key() -> bytes:
    import warnings

    raw = os.getenv("NUKEPII_VAULT_KEY", "")
    if raw:
        return hashlib.sha256(raw.encode()).digest()
    # ephemeral dev key (warn caller: not stable across restarts)
    warnings.warn(
        "NUKEPII_VAULT_KEY not set: using ephemeral dev key; "
        "vault tokens will not survive restarts and must not be "
        "relied on in production.",
        UserWarning,
        stacklevel=3,
    )
    return hashlib.sha256(b"nukepii-dev-vault").digest()


def _has_crypto() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore  # noqa: F401

        return True
    except Exception:
        return False


def _encrypt(plain: str, key: bytes) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plain.encode(), None)
        return base64.b64encode(nonce + ct).decode()
    except Exception:
        import warnings

        # stdlib fallback: NOT secure, clearly marked; for tests/offline only
        warnings.warn(
            "cryptography package missing: vault uses an INSECURE "
            "XOR+HMAC fallback (offline/tests only, never production).",
            UserWarning,
            stacklevel=3,
        )
        pad = hmac.new(key, b"vault-pad", hashlib.sha256).digest()
        data = plain.encode()
        xored = bytes(b ^ pad[i % len(pad)] for i, b in enumerate(data))
        return "FALLBACK:" + base64.b64encode(xored).decode()


def _decrypt(blob: str, key: bytes) -> str:
    if blob.startswith("FALLBACK:"):
        pad = hmac.new(key, b"vault-pad", hashlib.sha256).digest()
        raw = base64.b64decode(blob[len("FALLBACK:"):])
        return bytes(b ^ pad[i % len(pad)] for i, b in enumerate(raw)).decode()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

        raw = base64.b64decode(blob)
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(key).decrypt(nonce, ct, None).decode()
    except Exception as exc:
        raise ValueError("vault decrypt failed (wrong key?)") from exc


class TokenVault:
    """Deterministic reversible tokenizer with SQLite persistence."""

    def __init__(self, path: str | Path = "nukepii_vault.db", salt: str | None = None):
        self.path = str(path)
        self.salt = salt or os.getenv("NUKEPII_VAULT_SALT", "nukepii-vault-v1")
        self._key = _get_key()
        self.secure = _has_crypto()
        con = sqlite3.connect(self.path)
        try:
            con.execute(_VAULT_SCHEMA)
            con.commit()
        finally:
            con.close()

    def _token_for(self, value: str, pii_type: str) -> str:
        from nukepii.core.sanitizers import _PSEUDO_PREFIX

        prefix = _PSEUDO_PREFIX.get(pii_type.upper(), "PII")
        tok = hmac.new(self.salt.encode(), value.encode(),
                       hashlib.sha256).hexdigest()[:12]
        return f"{prefix}_{tok}"

    def tokenize(self, value: str, pii_type: str = "GENERIC") -> str:
        token = self._token_for(value, pii_type)
        con = sqlite3.connect(self.path)
        try:
            row = con.execute("SELECT ciphertext FROM tokens WHERE token=?", (token,)).fetchone()
            if row is None:
                con.execute("INSERT INTO tokens(token,ciphertext,pii_type,created_at) VALUES(?,?,?,?)",
                            (token, _encrypt(value, self._key), pii_type.upper(),
                             datetime.now(UTC).isoformat()))
                con.commit()
        finally:
            con.close()
        return token

    def detokenize(self, token: str) -> str:
        con = sqlite3.connect(self.path)
        try:
            row = con.execute("SELECT ciphertext FROM tokens WHERE token=?", (token,)).fetchone()
        finally:
            con.close()
        if row is None:
            raise KeyError(f"unknown token: {token}")
        return _decrypt(row[0], self._key)


__all__ = ["TokenVault"]
