"""Format-Preserving Encryption (lite, deterministic) — Faz-2.

Full NIST FF1/FF3-1 needs a Feistel network; this lite variant preserves
charset+length via HMAC-DRBG substitution per character class, which keeps
downstream validators (length, Luhn where applied separately) functional
for non-checksummed consumers.

  digits -> digits, lower -> lower, upper -> upper, other -> unchanged
Deterministic given (key, tweak). NOT a substitute for certified FF1 in
regulated environments — interface matches future `ff3` crate swap.

For checksum-carrying values (TC, credit card) use vault or hash instead
when strict validity must survive; FPE-lite keeps shape, not checksum.
"""

from __future__ import annotations

import hashlib
import hmac
import string

_DIGITS = string.digits
_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase


def _keystream(key: bytes, tweak: str, n: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < n:
        out += hmac.new(key, f"{tweak}:{ctr}".encode(), hashlib.sha256).digest()
        ctr += 1
    return out[:n]


def fpe_encrypt(value: str, key: str, tweak: str = "") -> str:
    kb = hashlib.sha256(key.encode()).digest()
    ks = _keystream(kb, tweak or "nukepii-fpe", len(value))
    res: list[str] = []
    for i, ch in enumerate(value):
        r = ks[i]
        if ch in _DIGITS:
            res.append(_DIGITS[(int(ch) + r) % 10])
        elif ch in _LOWER:
            res.append(_LOWER[(_LOWER.index(ch) + r) % 26])
        elif ch in _UPPER:
            res.append(_UPPER[(_UPPER.index(ch) + r) % 26])
        else:
            res.append(ch)
    return "".join(res)


def fpe_decrypt(token: str, key: str, tweak: str = "") -> str:
    kb = hashlib.sha256(key.encode()).digest()
    ks = _keystream(kb, tweak or "nukepii-fpe", len(token))
    res: list[str] = []
    for i, ch in enumerate(token):
        r = ks[i]
        if ch in _DIGITS:
            res.append(_DIGITS[(int(ch) - r) % 10])
        elif ch in _LOWER:
            res.append(_LOWER[(_LOWER.index(ch) - r) % 26])
        elif ch in _UPPER:
            res.append(_UPPER[(_UPPER.index(ch) - r) % 26])
        else:
            res.append(ch)
    return "".join(res)


__all__ = ["fpe_decrypt", "fpe_encrypt"]
