"""NukePII core sanitizers.

Decontamination engine with four strategies:

   1. Redaction / Masking (format-preserving) — ``mask_value`` / ``redact_text``.
      e.g. an email address -> masked form preserving shape.
  2. Salted hashing / HMAC — deterministic, non-reversible identifiers that
     preserve relational integrity (joins/group-bys still work after cleaning).
  3. Pseudonymization — deterministic, human-readable surrogate tokens
     (``USER_a3f9c1…``) backed by HMAC, consistent within a run/dataset.
  4. Differential-privacy noise — Laplace / Gaussian perturbation for numeric
     fields that preserves aggregate means while hiding exact values.

All functions are stdlib-only and operate on strings/numbers, so the
chunk-streaming pipeline can call them per-record without extra dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import random
import re
import secrets
from dataclasses import dataclass, field
from typing import Literal

from .detectors import Detection

SanitizeMode = Literal["mask", "hash", "pseudonymize", "redact", "noise", "vault", "fpe"]

_DEFAULT_SALT_BYTES = 16
_PSEUDO_PREFIX: dict[str, str] = {
    "EMAIL": "USER",
    "TR_PHONE": "PHONE",
    "US_PHONE": "PHONE",
    "INTL_PHONE": "PHONE",
    "TR_NATIONAL_ID": "ID",
    "TR_VKN": "TAX_ID",
    "DE_TAX_ID": "TAX_ID",
    "IN_PAN": "TAX_ID",
    "AU_TFN": "TAX_ID",
    "PL_PESEL": "ID",
    "US_SSN": "ID",
    "ES_NIF": "ID",
    "ES_NIE": "ID",
    "GB_NINO": "ID",
    "FR_NIR": "ID",
    "IT_FISCAL": "ID",
    "BR_CPF": "ID",
    "DE_IDNR": "ID",
    "NL_BSN": "ID",
    "BE_NATIONAL_ID": "ID",
    "FI_HETU": "ID",
    "SE_PERSONNUMMER": "ID",
    "NO_FODSELSNUMMER": "ID",
    "PT_NIF": "TAX_ID",
    "RO_CNP": "ID",
    "GR_AFM": "TAX_ID",
    "US_ABA": "BANK",
    "US_ITIN": "TAX_ID",
    "ISIN": "SECURITY",
    "SEDOL": "SECURITY",
    "IN_IFSC": "BANK",
    "AU_ABN": "TAX_ID",
    "CN_ID": "ID",
    "KR_RRN": "ID",
    "SG_NRIC": "ID",
    "IL_ID": "ID",
    "ZA_ID": "ID",
    "TH_ID": "ID",
    "TW_ID": "ID",
    "HK_ID": "ID",
    "JP_MY_NUMBER": "ID",
    "IMEI": "DEVICE",
    "VIN": "VEHICLE",
    "US_DEA": "HEALTH_ID",
    "US_MBI": "HEALTH_ID",
    "BTC_ADDRESS": "WALLET",
    "ETH_ADDRESS": "WALLET",
    "TELEGRAM_TOKEN": "KEY",
    "ANTHROPIC_KEY": "KEY",
    "HF_TOKEN": "KEY",
    "GITLAB_TOKEN": "KEY",
    "NPM_TOKEN": "KEY",
    "PYPI_TOKEN": "KEY",
    "TWILIO_KEY": "KEY",
    "SENDGRID_KEY": "KEY",
    "DISCORD_WEBHOOK": "URL",
    "CA_SIN": "ID",
    "IN_AADHAAR": "ID",
    "US_NPI": "HEALTH_ID",
    "HEALTH_INSURANCE_ID": "HEALTH_ID",
    "PASSPORT": "PASSPORT",
    "DRIVERS_LICENSE": "LICENSE",
    "CREDIT_CARD": "CARD",
    "AWS_API_KEY": "KEY",
    "GITHUB_TOKEN": "KEY",
    "STRIPE_KEY": "KEY",
    "OPENAI_KEY": "KEY",
    "GOOGLE_API_KEY": "KEY",
    "AZURE_KEY": "KEY",
    "PRIVATE_KEY": "KEY",
    "GENERIC_API_KEY": "KEY",
    "SLACK_WEBHOOK": "URL",
    "DATABASE_URL": "CONN_STR",
    "JWT": "TOKEN",
    "IPV4": "IP",
    "IPV6": "IP",
    "MAC_ADDRESS": "MAC",
    "COORDINATES": "GEO",
    "SWIFT_BIC": "SWIFT",
    "IBAN": "IBAN",
}


# ---------------------------------------------------------------------------
# 1. Masking / redaction (format-preserving)
# ---------------------------------------------------------------------------

def _mask_middle(s: str, keep_first: int = 1, keep_last: int = 1,
                 mask_char: str = "*") -> str:
    """Keep ``keep_first``/``keep_last`` chars, mask everything in between."""
    if not s:
        return s
    if len(s) <= keep_first + keep_last:
        return mask_char * len(s)
    prefix = s[:keep_first] if keep_first > 0 else ""
    suffix = s[-keep_last:] if keep_last > 0 else ""
    return prefix + mask_char * (len(s) - keep_first - keep_last) + suffix


def mask_email(value: str) -> str:
    """Mask an email while preserving shape (first/last chars kept, middle masked).

    Falls back to :func:`mask_generic` when no ``@`` is present.
    """
    if "@" not in value:
        return mask_generic(value)
    local, _, domain = value.partition("@")
    masked_local = _mask_middle(local, 1, 1) if len(local) > 2 else "*" * len(local)
    if "." in domain:
        first_label, _, rest = domain.partition(".")
        masked_label = _mask_middle(first_label, 1, 0) if first_label else ""
        masked_domain = masked_label + "." + rest  # keep TLD readable
    else:
        masked_domain = _mask_middle(domain, 1, 0)
    return f"{masked_local}@{masked_domain}"


def mask_phone(value: str) -> str:
    """Mask all but the last 2 digits, preserving separators.

    ``"+90 532 123 45 67"`` -> ``"+** *** *** ** 67"``.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 2:
        return "*" * len(value)
    keep = digits[-2:]
    out: list[str] = []
    digit_idx = 0
    total_digits = len(digits)
    for ch in value:
        if ch.isdigit():
            out.append(ch if digit_idx >= total_digits - 2 else "*")
            digit_idx += 1
        else:
            out.append(ch)
    _ = keep  # (kept for readability of intent)
    return "".join(out)


def mask_credit_card(value: str) -> str:
    """Mask all but the last 4 digits, preserving spaces/dashes.

    ``"4539 1488 0343 6467"`` -> ``"**** **** **** 6467"``.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 4:
        return "*" * len(value)
    out: list[str] = []
    digit_idx = 0
    for ch in value:
        if ch.isdigit():
            out.append(ch if digit_idx >= len(digits) - 4 else "*")
            digit_idx += 1
        else:
            out.append(ch)
    return "".join(out)


def mask_tr_national_id(value: str) -> str:
    """Mask a Turkish National ID, keeping first 2 + last 1: ``10000000146`` -> ``10*******46``....

    Actually keeps first 2 and last 1 digit: ``"10********6"`` (11 chars).
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11:
        return mask_generic(value)
    return digits[:2] + "*" * 8 + digits[-1:]


def mask_ip(value: str) -> str:
    """Mask the host portion: ``192.168.1.25`` -> ``192.168.1.***`` / IPv6 tail."""
    if "." in value and ":" not in value:  # IPv4
        parts = value.split(".")
        if len(parts) == 4:
            return ".".join([*parts[:3], "***"])
    if ":" in value:  # IPv6 — keep head, mask tail group(s)
        head, _, _ = value.rpartition(":")
        return f"{head}:****" if head else "****"
    return mask_generic(value)


def mask_jwt(value: str) -> str:
    """Keep JWT header (non-sensitive alg metadata), mask payload+signature."""
    parts = value.split(".")
    if len(parts) < 3:
        return mask_generic(value)
    return f"{parts[0]}.{'*' * 8}.{ '*' * 8}"


def mask_api_key(value: str) -> str:
    """Keep provider prefix / last 4 for traceability: ``AKIA...`` -> ``AKIA****************``."""
    if len(value) <= 8:
        return "*" * len(value)
    if re.match(r"(?:AKIA|ASIA|ABIA|ACCA)", value):
        return value[:4] + "*" * (len(value) - 4)
    return _mask_middle(value, 2, 4)


def mask_generic(value: str, keep_first: int = 1, keep_last: int = 1) -> str:
    """Fallback masker for unknown shapes."""
    return _mask_middle(value, keep_first, keep_last)


def mask_generic_id(value: str) -> str:
    """Mask a national-ID-like value, keeping first 2 + last 1 chars.

    Works for GB NINo, FR NIR, IT fiscal codes, BR CPF and DE IdNr —
    lengths vary, so the rule is shape-based, not length-based.
    """
    alnum = re.sub(r"\W", "", value)
    if len(alnum) < 4:
        return mask_generic(value)
    return value[:2] + "*" * (len(value) - 3) + value[-1:]


def mask_secret(value: str, keep_prefix: int = 4, keep_last: int = 2) -> str:
    """Mask a token/key, keeping a short prefix and tail for traceability.

    ``"ghp_AbCdEf…"`` -> ``"ghp_****…**"``. Separator-free by design so
    partial secrets never leak through formatting.
    """
    compact = value.strip()
    if len(compact) <= keep_prefix + keep_last:
        return "*" * len(compact)
    return compact[:keep_prefix] + "*" * (len(compact) - keep_prefix - keep_last) \
        + compact[-keep_last:] if keep_last else compact[:keep_prefix] + "*" * (len(compact) - keep_prefix)


def mask_url_secret(value: str) -> str:
    """Mask credentials inside URLs/connection strings, keep the shape.

    ``"postgres://user:pass@host/db"`` ->
    ``"postgres://user:****@host/db"``. Without a password part, falls
    back to masking the path/query tail.
    """
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*://[^/@\s]*:)([^@\s]+)(@.*)$", value)
    if m:
        return m.group(1) + "*" * max(len(m.group(2)), 4) + m.group(3)
    m2 = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*://[^/\s?]+)([/?.].*)$", value)
    if m2:
        return m2.group(1)
    return mask_secret(value, keep_prefix=8, keep_last=0)


def mask_mac(value: str) -> str:
    """Keep the vendor OUI (first 3 groups), mask the device part."""
    sep = ":" if ":" in value else "-"
    parts = value.split(sep)
    if len(parts) != 6:
        return mask_generic(value)
    return sep.join(parts[:3] + ["**"] * 3)


def mask_geo(value: str) -> str:
    """Coarsen a GPS pair to ~10 km precision (1 decimal place)."""
    m = re.fullmatch(r"\s*([+-]?\d+\.\d+)\s*([,;])\s*([+-]?\d+\.\d+)\s*", value)
    if not m:
        return mask_generic(value)
    return f"{float(m.group(1)):.1f}{m.group(2)} {float(m.group(3)):.1f}"


def mask_value(value: str, pii_type: str) -> str:
    """Dispatch to the format-preserving masker for ``pii_type``."""
    dispatch = {
        "EMAIL": mask_email,
        "TR_PHONE": mask_phone,
        "US_PHONE": mask_phone,
        "INTL_PHONE": mask_phone,
        "CREDIT_CARD": mask_credit_card,
        "TR_NATIONAL_ID": mask_tr_national_id,
        "TR_VKN": mask_generic_id,
        "DE_TAX_ID": mask_generic_id,
        "IN_PAN": mask_generic_id,
        "AU_TFN": mask_generic_id,
        "CA_SIN": mask_generic_id,
        "IN_AADHAAR": mask_generic_id,
        "US_NPI": mask_generic_id,
        "HEALTH_INSURANCE_ID": mask_generic,
        "PASSPORT": mask_generic_id,
        "DRIVERS_LICENSE": mask_generic,
        "GB_NINO": mask_generic_id,
        "FR_NIR": mask_generic_id,
        "IT_FISCAL": mask_generic_id,
        "BR_CPF": mask_generic_id,
        "DE_IDNR": mask_generic_id,
        "NL_BSN": mask_generic_id,
        "BE_NATIONAL_ID": mask_generic_id,
        "FI_HETU": mask_generic_id,
        "SE_PERSONNUMMER": mask_generic_id,
        "NO_FODSELSNUMMER": mask_generic_id,
        "PT_NIF": mask_generic_id,
        "RO_CNP": mask_generic_id,
        "GR_AFM": mask_generic_id,
        "US_ABA": mask_credit_card,
        "US_ITIN": mask_generic_id,
        "ISIN": mask_generic_id,
        "SEDOL": mask_generic_id,
        "IN_IFSC": mask_generic_id,
        "AU_ABN": mask_generic_id,
        "CN_ID": mask_generic_id,
        "KR_RRN": mask_generic_id,
        "SG_NRIC": mask_generic_id,
        "IL_ID": mask_generic_id,
        "ZA_ID": mask_generic_id,
        "TH_ID": mask_generic_id,
        "TW_ID": mask_generic_id,
        "HK_ID": mask_generic_id,
        "JP_MY_NUMBER": mask_generic_id,
        "IMEI": mask_generic_id,
        "VIN": mask_generic_id,
        "US_DEA": mask_generic_id,
        "US_MBI": mask_generic_id,
        "BTC_ADDRESS": mask_secret,
        "ETH_ADDRESS": mask_secret,
        "TELEGRAM_TOKEN": mask_secret,
        "ANTHROPIC_KEY": mask_secret,
        "HF_TOKEN": mask_secret,
        "GITLAB_TOKEN": mask_secret,
        "NPM_TOKEN": mask_secret,
        "PYPI_TOKEN": mask_secret,
        "TWILIO_KEY": mask_secret,
        "SENDGRID_KEY": mask_secret,
        "DISCORD_WEBHOOK": mask_url_secret,
        "IPV4": mask_ip,
        "IPV6": mask_ip,
        "MAC_ADDRESS": mask_mac,
        "COORDINATES": mask_geo,
        "SWIFT_BIC": mask_generic_id,
        "JWT": mask_jwt,
        "AWS_API_KEY": mask_api_key,
        "GITHUB_TOKEN": mask_secret,
        "STRIPE_KEY": mask_secret,
        "OPENAI_KEY": mask_secret,
        "GOOGLE_API_KEY": mask_secret,
        "AZURE_KEY": mask_secret,
        "PRIVATE_KEY": mask_secret,
        "SLACK_WEBHOOK": mask_url_secret,
        "DATABASE_URL": mask_url_secret,
        "GENERIC_API_KEY": mask_api_key,
    }
    return dispatch.get(pii_type.upper(), mask_generic)(value)


def redact_text(text: str, detections: list[Detection],
                placeholder: str = "[REDACTED]") -> str:
    """Replace every detection span with ``placeholder`` (back-to-front edit).

    Spans must follow the :mod:`detectors` contract (``start``/``end``).
    Sorting descending guarantees earlier offsets stay valid while editing.
    """
    if not text or not detections:
        return text
    out = text
    for det in sorted(detections, key=lambda d: d["start"], reverse=True):
        s, e = det["start"], det["end"]
        if 0 <= s <= e <= len(out):
            out = out[:s] + placeholder + out[e:]
    return out


def mask_text(text: str, detections: list[Detection]) -> str:
    """Replace every detection span with its format-preserving mask.

    Unlike :func:`redact_text`, output keeps the original shape (lengths of
    masked segments may differ slightly where maskers collapse labels).
    """
    if not text or not detections:
        return text
    out = text
    for det in sorted(detections, key=lambda d: d["start"], reverse=True):
        s, e = det["start"], det["end"]
        if 0 <= s <= e <= len(out):
            out = out[:s] + mask_value(out[s:e], det["type"]) + out[e:]
    return out


# ---------------------------------------------------------------------------
# 2. Salted hashing / HMAC (deterministic, non-reversible)
# ---------------------------------------------------------------------------

def generate_salt(nbytes: int = _DEFAULT_SALT_BYTES) -> str:
    """Generate a cryptographically random hex salt (to store alongside output)."""
    return secrets.token_hex(nbytes)


def hmac_hash(value: str, salt: str, algorithm: str = "sha256",
              length: int = 16) -> str:
    """HMAC ``value`` with ``salt`` -> truncated hex digest.

    Deterministic: the same (value, salt) pair always yields the same digest,
    so relational integrity (JOIN / GROUP BY) survives sanitization, while the
    original value cannot be recovered without the salt (and even then, only
    via brute force — use a strong random salt per dataset).
    """
    digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"),
                      getattr(hashlib, algorithm)).hexdigest()
    if length is not None:
        return digest[:length]
    return digest


# ---------------------------------------------------------------------------
# 3. Pseudonymization (deterministic surrogate tokens)
# ---------------------------------------------------------------------------

@dataclass
class Pseudonymizer:
    """Deterministic, collision-resistant surrogate-token mapper.

    The same input always maps to the same ``PREFIX_<hex>`` token for a given
    salt (relational integrity preserved); distinct inputs map to distinct
    tokens with overwhelming probability (12 hex chars = 48 bits).
    """

    salt: str = field(default_factory=generate_salt)
    token_length: int = 8

    def pseudonymize(self, value: str, pii_type: str = "GENERIC") -> str:
        prefix = _PSEUDO_PREFIX.get(pii_type.upper(), "PII")
        token = hmac_hash(value, self.salt, length=self.token_length)
        return f"{prefix}_{token}"

    def map_detections(self, detections: list[Detection]) -> dict[str, str]:
        """Build ``{original_value: surrogate}`` for a detection list."""
        mapping: dict[str, str] = {}
        for det in detections:
            v = det["value"]
            if v not in mapping:
                mapping[v] = self.pseudonymize(v, det["type"])
        return mapping


# ---------------------------------------------------------------------------
# 4. Differential-privacy noise (numeric fields)
# ---------------------------------------------------------------------------

def add_laplace_noise(value: float, epsilon: float = 1.0,
                      sensitivity: float = 1.0,
                      rng: random.Random | None = None) -> float:
    """Perturb ``value`` with Laplace(0, sensitivity/epsilon) noise.

    Smaller ``epsilon`` = stronger privacy, larger distortion. The noise has
    zero mean, so column averages stay approximately unbiased — the key
    differential-privacy property for analytics over sanitized exports.
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be > 0")
    r = rng or random
    # Inverse-CDF sampling: U ~ Uniform(-0.5, 0.5].
    u = r.random() - 0.5
    scale = sensitivity / epsilon
    # Laplace quantile: -scale * sign(u) * ln(1 - 2|u|)
    import math
    noise = -scale * (1 if u >= 0 else -1) * math.log(max(1 - 2 * abs(u), 1e-12))
    return value + noise


def add_gaussian_noise(value: float, sigma: float = 1.0,
                       rng: random.Random | None = None) -> float:
    """Perturb ``value`` with Gaussian N(0, sigma²) noise (approx. DP)."""
    r = rng or random
    return value + r.gauss(0.0, sigma)


def sanitize_numeric(value: float, epsilon: float = 1.0,
                     sensitivity: float = 1.0,
                     mechanism: str = "laplace",
                     rng: random.Random | None = None) -> float:
    """Sanitize one numeric field with the chosen noise mechanism."""
    if mechanism == "laplace":
        return add_laplace_noise(value, epsilon, sensitivity, rng)
    if mechanism == "gaussian":
        return add_gaussian_noise(value, sensitivity, rng)
    raise ValueError(f"Unknown mechanism: {mechanism!r} (use 'laplace'/'gaussian')")


# ---------------------------------------------------------------------------
# Façade: one entry point for streamer / CLI / web
# ---------------------------------------------------------------------------

@dataclass
class Sanitizer:
    """Configurable sanitizer façade used by the streamer, CLI and web layers.

    Parameters
    ----------
    mode:
        ``mask`` (format-preserving, default), ``redact`` (``[REDACTED]``),
        ``hash`` (HMAC hex), ``pseudonymize`` (surrogate tokens).
        ``noise`` applies only to numeric values via :meth:`sanitize_number`.
    salt: HMAC/pseudonym salt. Auto-generated when omitted — pass an explicit
        salt to keep mappings stable across chunked/streamed runs.
    """

    mode: SanitizeMode = "mask"
    salt: str = field(default_factory=generate_salt)
    pseudonymizer: Pseudonymizer | None = None
    redact_placeholder: str = "[REDACTED]"
    vault_path: str | None = None
    fpe_key: str | None = None

    def __post_init__(self) -> None:
        if self.pseudonymizer is None:
            self.pseudonymizer = Pseudonymizer(salt=self.salt)

    # -- string values --------------------------------------------------------

    def sanitize_value(self, value: str, pii_type: str) -> str:
        if self.mode == "mask":
            return mask_value(value, pii_type)
        if self.mode == "redact":
            return self.redact_placeholder
        if self.mode == "hash":
            return hmac_hash(value, self.salt)
        if self.mode == "pseudonymize":
            assert self.pseudonymizer is not None
            return self.pseudonymizer.pseudonymize(value, pii_type)
        if self.mode == "vault":
            from nukepii.core.vault import TokenVault

            vault = TokenVault(self.vault_path or "nukepii_vault.db", salt=self.salt)
            return vault.tokenize(value, pii_type)
        if self.mode == "fpe":
            from nukepii.core.fpe import fpe_encrypt

            return fpe_encrypt(value, key=self.fpe_key or self.salt, tweak=pii_type)
        raise ValueError(f"Unknown string mode: {self.mode!r}")

    def sanitize_text(self, text: str, detections: list[Detection]) -> str:
        """Sanitize full ``text`` according to ``mode``."""
        if not text or not detections:
            return text
        if self.mode == "redact":
            return redact_text(text, detections, self.redact_placeholder)
        if self.mode == "mask" or self.mode == "noise":
            # ``noise`` is numeric-only (see sanitize_number); for strings it
            # falls back to masking so scan/clean previews never 500.
            return mask_text(text, detections)
        # hash / pseudonymize: per-span replacement back-to-front.
        out = text
        mapping: dict[str, str] = {}
        for det in sorted(detections, key=lambda d: d["start"], reverse=True):
            s, e = det["start"], det["end"]
            if not 0 <= s <= e <= len(out):
                continue
            original = out[s:e]
            if original not in mapping:
                mapping[original] = self.sanitize_value(original, det["type"])
            out = out[:s] + mapping[original] + out[e:]
        return out

    # -- numeric values ---------------------------------------------------------

    def sanitize_number(self, value: float, epsilon: float = 1.0,
                        sensitivity: float = 1.0) -> float:
        if self.mode == "noise":
            return sanitize_numeric(value, epsilon, sensitivity)
        return value


__all__ = [
    "Pseudonymizer",
    "SanitizeMode",
    "Sanitizer",
    "add_gaussian_noise",
    "add_laplace_noise",
    "generate_salt",
    "hmac_hash",
    "mask_api_key",
    "mask_credit_card",
    "mask_email",
    "mask_generic",
    "mask_generic_id",
    "mask_geo",
    "mask_ip",
    "mask_jwt",
    "mask_mac",
    "mask_phone",
    "mask_secret",
    "mask_text",
    "mask_tr_national_id",
    "mask_url_secret",
    "mask_value",
    "redact_text",
    "sanitize_numeric",
]
