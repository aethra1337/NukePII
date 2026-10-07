"""NukePII core detectors.

Zero-Trust, local-first PII detection engine.

Two detection layers:
   1. Regex scanning  — emails, IPv4/IPv6, MACs, Turkish/US/international
      phones, JWTs, AWS / GitHub / Slack / Stripe / OpenAI / Google / Azure /
      Telegram / Anthropic / Hugging Face / GitLab / npm / PyPI / Twilio /
      SendGrid / Discord keys, database URLs, PEM private-key headers,
      generic API keys, ETH shape and IN IFSC codes.
   2. Algorithmic validation — Turkish National ID (Mod 10/11) and VKN
      (Mod 10), Credit Cards (Luhn), Polish PESEL (weighted Mod 10 + DOB
      range filter), US SSN (area/group/serial rules), ITIN ranges, ABA
      routing (3-7-1) and NPI (Luhn+80840), Spanish NIF/NIE (Mod 23),
      Portuguese NIF, Romanian CNP and Greek AFM (Mod 11), Dutch BSN
      (elfproef), Belgian National Number (Mod 97), Finnish HETU (Mod 31),
      Swedish Personnummer (Luhn) and Norwegian Fødselsnummer (double
      Mod 11), UK NINo (prefix rules), French NIR (Mod 97 key), Italian
      Codice Fiscale (check letter), Brazilian CPF (double Mod 11),
      German IdNr/Steuernummer (ISO 7064 MOD 11,10), Indian PAN and
      Aadhaar (Verhoeff), Australian TFN (weighted Mod 11) and ABN
      (Mod 89), ISIN (Luhn) and SEDOL (weighted Mod 10), Chinese ID
      (MOD 11-2), Korean RRN, Singapore NRIC, Israeli, South African
      (Luhn), Thai, Taiwanese, Hong Kong and Japanese My Number IDs,
      IMEI (context-gated Luhn), VIN (transliterated Mod 11), US DEA
      (summed check) and Medicare MBI shapes, BTC (Base58Check/bech32),
      Canadian SIN (Luhn), ICAO MRZ passport lines, SWIFT/BIC
      (ISO country) and GPS pairs, plus context-gated driver-license
      and health-insurance IDs and international IBAN (ISO 7064 Mod 97).

Every detection is a plain ``dict`` with the contract::

    {
        "type": str,        # e.g. "EMAIL", "CREDIT_CARD", ...
        "value": str,       # exact matched substring
        "start": int,       # start index in the source string
        "end": int,         # end index (exclusive) in the source string
        "confidence": float # 0.0 .. 1.0
    }

Design notes
------------
* All regexes are pre-compiled at import time.
* Algorithmic detectors first extract *candidates* with a cheap regex, then
  run the checksum validator — candidates that fail validation are discarded,
  which is what keeps false positives low on numeric data.
* :func:`scan_text` resolves overlapping matches deterministically: highest
  confidence wins, then longest match, then explicit type priority (algorithmic
  > cryptographic > contact > network). This prevents e.g. a phone-number
  substring from double-reporting inside a longer National ID.
* The module is dependency-free (stdlib only) so it can run inside the
  chunk-streaming pipeline without loading third-party state per chunk.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import date
from typing import TypedDict

# Optional Keccak-256 for EIP-55 (Faz-1 hardening): pure-stdlib fallback is
# shape-only; when pysha3/pycryptodome is present we upgrade to real checksum.
_keccak256 = None
_KECCAK_AVAILABLE = False
try:  # pysha3 (preferred, single-purpose)
    import sha3 as _sha3mod  # type: ignore

    _keccak256 = _sha3mod.keccak_256  # type: ignore[attr-defined]
    _KECCAK_AVAILABLE = True
except Exception:
    try:  # pycryptodome fallback
        from Crypto.Hash import keccak as _kmod  # type: ignore

        def _keccak256(data: bytes):  # type: ignore[misc]
            h = _kmod.new(digest_bits=256)
            h.update(data)
            return h

        _KECCAK_AVAILABLE = True
    except Exception:
        _keccak256 = None
        _KECCAK_AVAILABLE = False

# Optional Rust hot-path (maturin crate `rust/`, module `nukepii._native`).
# Guarded import only — no processes, no binaries at runtime. When the
# extension is absent (or raises), every validator below silently uses the
# pure-Python implementation with identical semantics.
try:
    from nukepii.core._bridge import mod as _native_mod_fn
except Exception:  # pragma: no cover - bridge is always importable in practice
    def _native_mod_fn():  # type: ignore[misc]
        return None


def _native():
    """Return the native module or None (never raises)."""
    try:
        return _native_mod_fn()
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Public contract
# ---------------------------------------------------------------------------

class Detection(TypedDict):
    type: str
    value: str
    start: int
    end: int
    confidence: float


@dataclass(frozen=True)
class PatternSpec:
    """Binds a PII type to its compiled regex + confidence + priority."""

    pii_type: str
    pattern: re.Pattern[str]
    confidence: float
    priority: int  # higher = wins overlap resolution on ties
    description: str


# Severity weights (0-10) used by the web dashboard Risk Score gauge.
# Risk = min(100, PII_density * weighted_severity_factor). Kept here so CLI,
# streamer and web all share one source of truth.
SEVERITY_WEIGHTS: dict[str, float] = {
    "TR_NATIONAL_ID": 10.0,
    "TR_VKN": 10.0,
    "PL_PESEL": 10.0,
    "US_SSN": 10.0,
    "ES_NIF": 10.0,
    "ES_NIE": 10.0,
    "GB_NINO": 10.0,
    "FR_NIR": 10.0,
    "IT_FISCAL": 10.0,
    "BR_CPF": 10.0,
    "DE_IDNR": 10.0,
    "IN_PAN": 10.0,
    "IN_AADHAAR": 10.0,
    "AU_TFN": 10.0,
    "CA_SIN": 10.0,
    "NL_BSN": 10.0,
    "BE_NATIONAL_ID": 10.0,
    "FI_HETU": 10.0,
    "SE_PERSONNUMMER": 10.0,
    "NO_FODSELSNUMMER": 10.0,
    "PT_NIF": 10.0,
    "RO_CNP": 10.0,
    "GR_AFM": 10.0,
    "US_ABA": 8.0,
    "US_ITIN": 10.0,
    "ISIN": 8.0,
    "SEDOL": 8.0,
    "IN_IFSC": 8.0,
    "AU_ABN": 9.0,
    "CN_ID": 10.0,
    "KR_RRN": 10.0,
    "SG_NRIC": 10.0,
    "IL_ID": 10.0,
    "ZA_ID": 10.0,
    "TH_ID": 10.0,
    "TW_ID": 10.0,
    "HK_ID": 10.0,
    "JP_MY_NUMBER": 10.0,
    "IMEI": 6.0,
    "VIN": 6.0,
    "US_DEA": 9.0,
    "US_MBI": 9.0,
    "BTC_ADDRESS": 8.0,
    "ETH_ADDRESS": 7.0,
    "TELEGRAM_TOKEN": 9.0,
    "ANTHROPIC_KEY": 9.0,
    "HF_TOKEN": 9.0,
    "GITLAB_TOKEN": 9.0,
    "NPM_TOKEN": 9.0,
    "PYPI_TOKEN": 9.0,
    "TWILIO_KEY": 9.0,
    "SENDGRID_KEY": 9.0,
    "DISCORD_WEBHOOK": 9.0,
    "CREDIT_CARD": 9.0,
    "AWS_API_KEY": 9.0,
    "GITHUB_TOKEN": 9.0,
    "STRIPE_KEY": 9.0,
    "OPENAI_KEY": 9.0,
    "GOOGLE_API_KEY": 9.0,
    "AZURE_KEY": 9.0,
    "PRIVATE_KEY": 9.0,
    "US_NPI": 9.0,
    "PASSPORT": 9.0,
    "IBAN": 9.0,
    "DE_TAX_ID": 9.0,
    "JWT": 8.0,
    "DRIVERS_LICENSE": 8.0,
    "HEALTH_INSURANCE_ID": 8.0,
    "SWIFT_BIC": 8.0,
    "DATABASE_URL": 8.0,
    "SLACK_WEBHOOK": 8.0,
    "GENERIC_API_KEY": 7.0,
    "COORDINATES": 6.0,
    "EMAIL": 5.0,
    "TR_PHONE": 5.0,
    "US_PHONE": 5.0,
    "INTL_PHONE": 5.0,
    "MAC_ADDRESS": 4.0,
    "IPV4": 3.0,
    "IPV6": 3.0,
}

PII_TYPES: Sequence[str] = tuple(SEVERITY_WEIGHTS.keys())  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Regions & global compliance tagging
# ---------------------------------------------------------------------------

#: Selectable scan regions. ``"ALL"`` enables every detector; any other
#: selection enables that region's detectors plus the ``GLOBAL`` ones
#: (emails, cards, IPs, JWTs, API keys) which are universal.
REGIONS: Sequence[str] = ("ALL", "TR", "PL", "US", "ES", "EU",
                           "GB", "FR", "DE", "IT", "BR", "IN", "AU", "CA",
                           "CN", "KR", "SG", "IL", "ZA", "TH", "TW", "HK", "JP")

#: Home region of each PII type. The type prefix doubles as the region tag
#: (``PL_PESEL`` -> Poland, ``US_SSN`` -> United States, …).
REGION_OF_TYPE: dict[str, str] = {
    "TR_NATIONAL_ID": "TR",
    "TR_PHONE": "TR",
    "TR_VKN": "TR",
    "PL_PESEL": "PL",
    "US_SSN": "US",
    "US_PHONE": "US",
    "US_NPI": "US",
    "US_ABA": "US",
    "US_ITIN": "US",
    "US_DEA": "US",
    "US_MBI": "US",
    "ES_NIF": "ES",
    "ES_NIE": "ES",
    "GB_NINO": "GB",
    "FR_NIR": "FR",
    "DE_IDNR": "DE",
    "DE_TAX_ID": "DE",
    "IT_FISCAL": "IT",
    "BR_CPF": "BR",
    "IN_PAN": "IN",
    "IN_AADHAAR": "IN",
    "IN_IFSC": "IN",
    "AU_TFN": "AU",
    "AU_ABN": "AU",
    "CA_SIN": "CA",
    "CN_ID": "CN",
    "KR_RRN": "KR",
    "SG_NRIC": "SG",
    "IL_ID": "IL",
    "ZA_ID": "ZA",
    "TH_ID": "TH",
    "TW_ID": "TW",
    "HK_ID": "HK",
    "JP_MY_NUMBER": "JP",
    "IMEI": "GLOBAL",
    "VIN": "GLOBAL",
    "NL_BSN": "EU",
    "BE_NATIONAL_ID": "EU",
    "FI_HETU": "EU",
    "SE_PERSONNUMMER": "EU",
    "NO_FODSELSNUMMER": "EU",
    "PT_NIF": "EU",
    "RO_CNP": "EU",
    "GR_AFM": "EU",
    "IBAN": "EU",
    "CREDIT_CARD": "GLOBAL",
    "EMAIL": "GLOBAL",
    "IPV4": "GLOBAL",
    "IPV6": "GLOBAL",
    "INTL_PHONE": "GLOBAL",
    "PASSPORT": "GLOBAL",
    "DRIVERS_LICENSE": "GLOBAL",
    "HEALTH_INSURANCE_ID": "GLOBAL",
    "GITHUB_TOKEN": "GLOBAL",
    "SLACK_WEBHOOK": "GLOBAL",
    "STRIPE_KEY": "GLOBAL",
    "OPENAI_KEY": "GLOBAL",
    "GOOGLE_API_KEY": "GLOBAL",
    "AZURE_KEY": "GLOBAL",
    "DATABASE_URL": "GLOBAL",
    "PRIVATE_KEY": "GLOBAL",
    "MAC_ADDRESS": "GLOBAL",
    "COORDINATES": "GLOBAL",
    "SWIFT_BIC": "GLOBAL",
    "JWT": "GLOBAL",
    "AWS_API_KEY": "GLOBAL",
    "GENERIC_API_KEY": "GLOBAL",
    "ISIN": "GLOBAL",
    "SEDOL": "GLOBAL",
    "BTC_ADDRESS": "GLOBAL",
    "ETH_ADDRESS": "GLOBAL",
    "TELEGRAM_TOKEN": "GLOBAL",
    "ANTHROPIC_KEY": "GLOBAL",
    "HF_TOKEN": "GLOBAL",
    "GITLAB_TOKEN": "GLOBAL",
    "NPM_TOKEN": "GLOBAL",
    "PYPI_TOKEN": "GLOBAL",
    "TWILIO_KEY": "GLOBAL",
    "SENDGRID_KEY": "GLOBAL",
    "DISCORD_WEBHOOK": "GLOBAL",
}

#: Global compliance frameworks relevant to each PII type, for the scan
#: report payload: GDPR (EU), KVKK (Turkey), CCPA (California/US).
COMPLIANCE_OF_TYPE: dict[str, list[str]] = {
    "TR_NATIONAL_ID": ["KVKK"],
    "TR_PHONE": ["KVKK"],
    "TR_VKN": ["KVKK"],
    "PL_PESEL": ["GDPR"],
    "ES_NIF": ["GDPR"],
    "ES_NIE": ["GDPR"],
    "GB_NINO": ["GDPR"],
    "FR_NIR": ["GDPR"],
    "DE_IDNR": ["GDPR"],
    "DE_TAX_ID": ["GDPR"],
    "IT_FISCAL": ["GDPR"],
    "IN_PAN": ["GDPR"],
    "IN_AADHAAR": ["GDPR"],
    "AU_TFN": ["GDPR"],
    "BR_CPF": ["LGPD"],
    "NL_BSN": ["GDPR"],
    "BE_NATIONAL_ID": ["GDPR"],
    "FI_HETU": ["GDPR"],
    "SE_PERSONNUMMER": ["GDPR"],
    "NO_FODSELSNUMMER": ["GDPR"],
    "PT_NIF": ["GDPR"],
    "RO_CNP": ["GDPR"],
    "GR_AFM": ["GDPR"],
    "US_ABA": ["CCPA"],
    "US_ITIN": ["CCPA"],
    "ISIN": ["GDPR", "CCPA"],
    "SEDOL": ["GDPR", "CCPA"],
    "IN_IFSC": ["GDPR"],
    "AU_ABN": ["GDPR"],
    "CN_ID": ["GDPR"],
    "KR_RRN": ["GDPR"],
    "SG_NRIC": ["GDPR"],
    "IL_ID": ["GDPR"],
    "ZA_ID": ["GDPR"],
    "TH_ID": ["GDPR"],
    "TW_ID": ["GDPR"],
    "HK_ID": ["GDPR"],
    "JP_MY_NUMBER": ["GDPR"],
    "IMEI": ["GDPR", "CCPA"],
    "VIN": ["GDPR", "CCPA"],
    "US_DEA": ["HIPAA"],
    "US_MBI": ["HIPAA"],
    "BTC_ADDRESS": ["GDPR", "CCPA"],
    "ETH_ADDRESS": ["GDPR", "CCPA"],
    "TELEGRAM_TOKEN": ["GDPR", "CCPA"],
    "ANTHROPIC_KEY": ["GDPR", "CCPA"],
    "HF_TOKEN": ["GDPR", "CCPA"],
    "GITLAB_TOKEN": ["GDPR", "CCPA"],
    "NPM_TOKEN": ["GDPR", "CCPA"],
    "PYPI_TOKEN": ["GDPR", "CCPA"],
    "TWILIO_KEY": ["GDPR", "CCPA"],
    "SENDGRID_KEY": ["GDPR", "CCPA"],
    "DISCORD_WEBHOOK": ["GDPR", "CCPA"],
    "IBAN": ["GDPR"],
    "SWIFT_BIC": ["GDPR"],
    "US_SSN": ["CCPA"],
    "US_PHONE": ["CCPA"],
    "CA_SIN": ["CCPA"],
    "DRIVERS_LICENSE": ["GDPR", "CCPA"],
    "PASSPORT": ["GDPR", "CCPA"],
    "US_NPI": ["HIPAA"],
    "HEALTH_INSURANCE_ID": ["HIPAA"],
    "EMAIL": ["GDPR", "CCPA"],
    "CREDIT_CARD": ["GDPR", "CCPA"],
    "INTL_PHONE": ["GDPR", "CCPA"],
    "MAC_ADDRESS": ["GDPR", "CCPA"],
    "COORDINATES": ["GDPR", "CCPA"],
    "IPV4": ["GDPR", "CCPA"],
    "IPV6": ["GDPR", "CCPA"],
    "JWT": ["GDPR", "CCPA"],
    "AWS_API_KEY": ["GDPR", "CCPA"],
    "GITHUB_TOKEN": ["GDPR", "CCPA"],
    "STRIPE_KEY": ["GDPR", "CCPA"],
    "OPENAI_KEY": ["GDPR", "CCPA"],
    "GOOGLE_API_KEY": ["GDPR", "CCPA"],
    "AZURE_KEY": ["GDPR", "CCPA"],
    "DATABASE_URL": ["GDPR", "CCPA"],
    "PRIVATE_KEY": ["GDPR", "CCPA"],
    "SLACK_WEBHOOK": ["GDPR", "CCPA"],
    "GENERIC_API_KEY": ["GDPR", "CCPA"],
}


def normalize_regions(regions: str | Collection[str]) -> frozenset[str]:
    """Normalize a region selection (``"PL"``, ``"tr,us"``, ``{"ES"}`` …).

    Raises :class:`ValueError` on unknown region names. ``"ALL"`` may be
    combined but dominates (it enables every detector).
    """
    if isinstance(regions, str):
        parts = [p.strip().upper() for p in regions.split(",") if p.strip()]
    else:
        parts = [str(p).strip().upper() for p in regions]
    if not parts:
        raise ValueError(f"Empty region selection. Choose from {list(REGIONS)}.")
    unknown = [p for p in parts if p not in REGIONS]
    if unknown:
        raise ValueError(f"Unknown region(s) {unknown}. Choose from {list(REGIONS)}.")
    return frozenset(parts)


# Custom-rule compliance registry (populated per PIIDetector init, Faz-1).
_CUSTOM_COMPLIANCE: dict[str, list[str]] = {}


def compliance_for(pii_type: str) -> list[str]:
    """Return the compliance frameworks relevant to ``pii_type``."""
    key = pii_type.upper()
    if key in COMPLIANCE_OF_TYPE:
        return list(COMPLIANCE_OF_TYPE[key])
    return list(_CUSTOM_COMPLIANCE.get(key, []))


def compliance_summary(breakdown: dict[str, int]) -> dict[str, int]:
    """Aggregate detection counts per compliance framework."""
    totals = {"GDPR": 0, "KVKK": 0, "CCPA": 0, "LGPD": 0, "HIPAA": 0}
    for pii_type, count in breakdown.items():
        for framework in COMPLIANCE_OF_TYPE.get(pii_type, []):
            totals[framework] += count
    return totals


# ---------------------------------------------------------------------------
# Regex layer
# ---------------------------------------------------------------------------

# Email: pragmatic RFC-5322 subset. Requires TLD to avoid matching "user@localhost"
# noise in logs; case-insensitive.
_EMAIL_RE = re.compile(
    # Length-bounded (local ≤64 per RFC 5321, domain ≤253): unbounded
    # ``+`` backtracks O(n^2) on long @-less runs and hangs the workers.
    r"(?P<email>[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,})",
    re.IGNORECASE,
)

# IPv4: strict octet check 0-255, word-boundary guarded.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(rf"(?<!\d)(?P<ipv4>{_OCTET}(?:\.{_OCTET}){{3}})(?!\d)")

# IPv6: covers full (8 groups), compressed (::), and mixed forms. This is a
# best-effort pattern tuned for logs/dumps — not a full RFC 4291 validator.
# NOTE: alternatives are ordered longest-first — Python `re` alternation is
# ordered, not longest-match, so the bare `grp::` suffix branch must come last
# or inputs like "fe80::1" would only match the "fe80::" prefix.
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?P<ipv6>"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"          # full 1:2:3:4:5:6:7:8
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"       # single :: with suffix (fe80::1)
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"      # :: prefix variants
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                       # trailing :: (fe80::)
    r")"
    r"(?![0-9A-Fa-f:])",
)

# Turkish phone: +90 / 0090 / 0 prefixes, 5xx mobile (and 312-style landlines),
# tolerates spaces/dashes/parens: "+90 532 123 45 67", "0532-123-45-67", "(532) 1234567".
_TR_PHONE_RE = re.compile(
    r"(?P<phone>"
    r"(?:\+90|0090|0)?"          # country / trunk prefix (optional)
    r"[\s\-()]*"
    r"5\d{2}"                    # Turkish mobile block 5xx
    r"[\s\-()]*\d{3}"
    r"[\s\-()]*\d{2}"
    r"[\s\-()]*\d{2}"
    r")"
)

# JWT: three base64url segments separated by dots, must start with eyJ (JSON header).
_JWT_RE = re.compile(
    r"(?P<jwt>eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\\-]*)"
)

# US NANP phone: +1 / 1 prefix, or parenthesized area code, or fully
# separated NNN-NNN-NNNN. Area and exchange codes must start with 2-9
# (NXX rule), which is what keeps random digit runs out.
_US_PHONE_RE = re.compile(
    r"(?<!\d)(?P<usphone>"
    r"(?:\+1|1)[\s.\-]*\(?([2-9]\d{2})\)?[\s.\-]*([2-9]\d{2})[\s.\-]*(\d{4})"
    r"|(?:\( ?([2-9]\d{2}) ?\))[\s.\-]*([2-9]\d{2})[\s.\-]*(\d{4})"
    r"|([2-9]\d{2})[\s.\-]([2-9]\d{2})[\s.\-](\d{4})"
    r")(?!\d)"
)

# International phone catch-all (GLOBAL): must start with "+" (E.164 style),
# 7-15 digits after it. Lower confidence/priority so national detectors win.
_INTL_PHONE_RE = re.compile(
    r"(?P<intl>\+(?:\d[\s.\-()]*){7,15})(?![\d])"
)

# AWS Access Key ID: AKIA/ASIA/ABIA/ACCA + 16 uppercase alphanumerics.
_AWS_KEY_RE = re.compile(r"(?P<aws>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})")

# Generic API key / secret assignment:  key = "....", api-key: '....'
# Value must be >=16 chars with enough entropy to avoid flagging plain words.
_GENERIC_API_KEY_RE = re.compile(
    r"(?i)(?P<keyname>(?:api[\-_]?key|secret|token|passwd|password|auth[\-_]?token))"
    r"\s*[:=]\s*['\"]?"
    r"(?P<secret>[A-Za-z0-9_\-\.~+/=]{16,})"
    r"['\"]?",
)

# --- Candidate extractors for algorithmic validators ------------------------

# TR National ID candidate: exactly 11 digits, first digit != 0, word guarded.
# Validation (Mod10/Mod11) happens in code — regex alone is insufficient.
_TR_ID_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<trid>[1-9]\d{10})(?!\d)")

# Credit card candidate: 13-19 digits possibly separated by spaces/dashes.
# Luhn validation happens in code.
_CC_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?P<cc>(?:\d[\s\-]?){13,19})(?!\d)"
)

# --- International ID candidates (validated in code) -----------------------

# PESEL (Poland): any 11-digit run (leading zeros allowed — unlike TR IDs).
_PESEL_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<pesel>\d{11})(?!\d)")

# US SSN: dashed/spaced AAA-GG-SSSS only. A bare 9-digit run is far too
# FP-prone (order numbers, subsequences of longer IDs), so it is excluded.
_SSN_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<ssn>\d{3}[- ]\d{2}[- ]\d{4})(?!\d)")

# Spanish NIF: 8 digits + control letter. NIE: X/Y/Z + 7 digits + letter.
# Alnum-guarded so "A12345678Z9" style substrings never match.
_NIF_CANDIDATE_RE = re.compile(r"(?<![A-Z0-9])(?P<nif>\d{8}[A-Z])(?![A-Z0-9])", re.IGNORECASE)
_NIE_CANDIDATE_RE = re.compile(r"(?<![A-Z0-9])(?P<nie>[XYZ]\d{7}[A-Z])(?![A-Z0-9])", re.IGNORECASE)

# IBAN: 2-letter country + 2 check digits + BBAN in (optional) groups of 4
# with a possible short tail (covers spaced print format and compact form).
_IBAN_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<iban>[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4})+(?: ?[A-Z0-9]{1,3})?)(?![A-Z0-9])",
    re.IGNORECASE,
)

# --- Global ID candidates (validated in code) ---------------------------

# UK National Insurance number: 2 prefix letters (restricted sets) + 6
# digits + suffix A-D. Spaces between groups are optional.
_NINO_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<nino>[A-CEGHJ-PR-TW-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D])(?![A-Z0-9])",
    re.IGNORECASE,
)

# French NIR (INSEE): 15 chars starting with 1/2, spaces allowed; dept may
# be 2A/2B (Corsica). Key validated in code (Mod 97).
_NIR_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Z])(?P<nir>[12](?:[0-9A-Z] ?){14})(?![0-9A-Z])",
    re.IGNORECASE,
)

# Italian Codice Fiscale: 6 letters + 2 digits + month letter + 2 digits +
# birthplace code (letter + 3 digits) + check letter.
_FISCAL_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<fisc>[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z])(?![A-Z0-9])",
    re.IGNORECASE,
)

# Brazilian CPF: 11 digits, plain or dotted/dashed (000.000.000-00).
_CPF_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?P<cpf>\d{3}[.\-]?\d{3}[.\-]?\d{3}[.\- ]?\d{2})(?!\d)"
)

# German Steuerliche Identifikationsnummer: 11 digits, first != 0.
# ISO 7064 MOD 11,10 validated in code.
_DEIDNR_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<deid>[1-9]\d{10})(?!\d)")

# --- Tax & corporate ID candidates --------------------------------------

# Turkish VKN (Vergi Kimlik No): exactly 10 digits, first != 0.
# Letter guards keep token tails (sk-proj-…0123456789) routed to secrets.
_VKN_CANDIDATE_RE = re.compile(r"(?<![\dA-Za-z])(?P<vkn>[1-9]\d{9})(?![\dA-Za-z])")

# German Steuernummer: 10-13 digits, always written with separators
# (10/123/4567, 123/4567/8901 …). The separator requirement keeps plain
# 11-digit runs routed to DE_IDNR instead.
_DETAX_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?P<detax>\d{2,4}[/.\- ]\d{2,4}[/.\- ]\d{2,5})(?!\d)"
)

# Indian PAN: 5 letters + 4 digits + 1 letter (4th letter = holder class).
_PAN_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<pan>[A-Z]{5}[0-9]{4}[A-Z])(?![A-Z0-9])",
    re.IGNORECASE,
)

# Australian TFN: 9 digits, optionally grouped (xxx xxx xxx).
_TFN_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<tfn>\d{3} ?\d{3} ?\d{3})(?![\dA-Za-z])"
)

# Canadian SIN: 9 digits starting 1-7, plain or dashed/spaced.
_SIN_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<sin>[1-7]\d{2}[- ]?\d{3}[- ]?\d{3})(?![\dA-Za-z])"
)

# --- EU national ID candidates (validated in code) ------------------------

# Dutch BSN: 9 digits (leading zeros allowed). Letter guards keep token
# tails out; elfproef validated in code.
_BSN_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<bsn>\d{9})(?![\dA-Za-z])"
)

# Belgian National Number: 11 digits YYMMDD-XXX-CC, plain or dotted/dashed
# (93.05.18-223.64). Mod 97 validated in code (with +2e9 for post-1999).
_BE_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<be>\d{2}[.\- ]?\d{2}[.\- ]?\d{2}[.\- ]?\d{3}[.\- ]?\d{2})(?![\dA-Za-z])"
)

# Finnish HETU: DDMMYY + century sign (+/-/A) + individual + check char.
# The century sign keeps the shape distinctive (no bare-digit clash).
_HETU_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<hetu>\d{6}[+\-A]\d{3}[0-9A-Z])(?![A-Z0-9])",
    re.IGNORECASE,
)

# Swedish Personnummer: YYMMDD-NNNN (+ for 100+), 10 or 12 digits.
# 12-digit alternative first (ordered alternation, longest-first).
_SE_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?P<se>(?:19|20)\d{6}[-+]?\d{4}|\d{6}[-+]?\d{4})(?!\d)"
)

# Norwegian Fødselsnummer: 11 digits DDMMYY + individ + 2 Mod-11 checks.
_NO_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<no>\d{11})(?!\d)")

# Portuguese NIF: 9 digits, first != 0. Letter guards (TFN/SIN turf).
_PT_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<pt>[1-9]\d{8})(?![\dA-Za-z])"
)

# Romanian CNP: 13 digits S YY MM DD CC NNN C. Length keeps it clear of
# 11-digit IDs; 13-digit card runs are re-tested by Luhn separately.
_RO_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<ro>\d{13})(?!\d)")

# Greek AFM: 9 digits, first != 0. Letter guards (TFN/SIN/PT turf).
_GR_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<gr>[1-9]\d{8})(?![\dA-Za-z])"
)

# --- Financial identifier candidates (validated in code, IFSC direct) ----

# US ABA routing number: 9 digits. Letter guards (BSN/PT turf); district
# range + 3-7-1 checksum validated in code.
_ABA_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<aba>\d{9})(?![\dA-Za-z])"
)

# US ITIN: 9XX-7X/8X-XXXX, dashed/spaced only (bare 9-digit runs stay out,
# exactly like SSN). Middle group 70-88, 90-92, 94-99.
_ITIN_CANDIDATE_RE = re.compile(
    r"(?<!\d)(?P<itin>9\d{2}[- ](?:7\d|8[0-8]|90|91|92|94|95|96|97|98|99)[- ]\d{4})(?!\d)"
)

# ISIN: 2 letters + 9 alnum + check digit (12 chars). Luhn validated in code.
_ISIN_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<isin>[A-Z]{2}[A-Z0-9]{9}\d)(?![A-Z0-9])"
)

# SEDOL: 7 consonant/digit chars (vowels never issued). Weighted Mod 10
# validated in code; digit requirement keeps English words out.
_SEDOL_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<sedol>[A-Z0-9]{7})(?![A-Z0-9])",
    re.IGNORECASE,
)

# Indian IFSC: 4-letter bank code + literal 0 + 6-char branch. No checksum
# exists, but the shape is specific enough for a direct regex detector.
_IFSC_RE = re.compile(
    r"(?<![A-Z0-9])(?P<ifsc>[A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])"
)

# Australian ABN: 11 digits, first != 0. Weighted Mod 89 validated in code.
_ABN_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<abn>[1-9]\d{10})(?!\d)")

# --- APAC/MEA ID + device candidates (validated in code) ------------------

# Chinese Resident ID: 17 digits + digit/X (18 chars). Letter guards.
_CN_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<cn>\d{17}[0-9X])(?![\dA-Za-z])",
    re.IGNORECASE,
)

# Korean RRN: 13 digits YYMMDD-SBBBBBC. Length separates it from 11-digit IDs.
_KR_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<kr>\d{13})(?!\d)")

# Singapore NRIC/FIN: S/T/F/G + 7 digits + check letter (M series excluded —
# its checksum rule is not publicly stable; documented trade-off).
_SG_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<sg>[STFG]\d{7}[A-Z])(?![A-Z0-9])",
    re.IGNORECASE,
)

# Israeli ID: 8-9 digits in scans (7-digit runs are usually order IDs and
# Luhn-passes 10% of them; the validator still accepts shorter legacy IDs).
# Letter guards (BSN/PT turf for the 9-digit form).
_IL_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<il>\d{8,9})(?![\dA-Za-z])"
)

# South African ID: 13 digits YYMMDD SSSS 0/1 8 C (Luhn).
_ZA_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<za>\d{13})(?!\d)")

# Thai ID: 13 digits, first 1-8. Letter-free runs (card turf re-tested).
_TH_CANDIDATE_RE = re.compile(r"(?<!\d)(?P<th>[1-8]\d{12})(?!\d)")

# Taiwan ID: 1 letter + 9 digits (resident certs share the shape).
_TW_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<tw>[A-Z]\d{9})(?![A-Z0-9])",
    re.IGNORECASE,
)

# Hong Kong ID: 1-2 letters + 6 digits + check in optional parens.
_HK_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<hk>[A-Z]{1,2}\d{6}\(?[0-9A]\)?)(?![A-Z0-9])",
    re.IGNORECASE,
)

# Japanese My Number: 12 digits. (Aadhaar needs a 2-9 start; 12-digit SE
# forms need a 19/20 prefix — joint-valid collisions stay negligible.)
_JP_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<jp>\d{12})(?![\dA-Za-z])"
)

# IMEI: exactly 15 digits, but only with an explicit label nearby — a bare
# 15-digit Luhn run is card-shaped (Amex) and stays CREDIT_CARD. Same
# context-gating philosophy as driver-license / health IDs.
_IMEI_CONTEXT_RE = re.compile(
    r"(?i)\b(?:imei|international mobile equipment(?: identity)?)"
    r"(?:\s*(?:no\.?|number|#))?\s*[:#\-]?\s*['\"]?(?P<imei>\d{15})['\"]?"
)

# VIN: 17 chars, no I/O/Q (never used). Position-9 check validated in code.
_VIN_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<vin>[A-HJ-NPR-Z0-9]{17})(?![A-Z0-9])",
    re.IGNORECASE,
)

# --- Health + crypto candidates (validated in code) -----------------------

# US DEA number: registrant letter + prescriber initial + 7 digits.
# First letter restricted to issued registrant classes.
_DEA_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<dea>[ABCDEFGHJKLMPRSTUX][A-Z]\d{7})(?![A-Z0-9])",
    re.IGNORECASE,
)

# US Medicare MBI: 11 chars C-A-AN-N-A-AN-N-A-AN-N-N, dashes optional.
# Excluded letters S/L/O/I/B/Z enforced in code.
_MBI_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<mbi>\d[A-Z][A-Z0-9]\d[A-Z][A-Z0-9]\d[A-Z][A-Z0-9]\d\d"
    r"|\d[A-Z][A-Z0-9]\d-[A-Z][A-Z0-9]\d-[A-Z][A-Z0-9]\d\d)(?![A-Z0-9])",
    re.IGNORECASE,
)

# Bitcoin: Base58 P2PKH/P2SH (1…/3…) or bech32 (bc1…). Double-SHA256 /
# bech32 polymod checksums validated in code (stdlib hashlib only).
_BTC_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<btc>[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    r"|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71})(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# Ethereum: 0x + 40 hex. No checksum without Keccak (not in stdlib), so
# shape-only at reduced confidence — documented trade-off.
_ETH_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<eth>0x[0-9a-fA-F]{40})(?![A-Za-z0-9])"
)

# Indian Aadhaar: 12 digits starting 2-9, plain or 4-4-4 grouped.
_AADHAAR_CANDIDATE_RE = re.compile(
    r"(?<![\dA-Za-z])(?P<aad>[2-9]\d{3} ?\d{4} ?\d{4}|[2-9]\d{11})(?![\dA-Za-z])"
)

# US NPI: 10 digits starting 1/2 (Luhn over 80840+first9 in code).
_NPI_CANDIDATE_RE = re.compile(r"(?<![\dA-Za-z])(?P<npi>[12]\d{9})(?![\dA-Za-z])")

# --- Secrets: fixed-format tokens (no checksum, strict shape) -----------

_TELEGRAM_TOKEN_RE = re.compile(
    r"(?P<telegram>\b\d{8,10}:[A-Za-z0-9\-_]{32,})(?![A-Za-z0-9\-_])"
)

_ANTHROPIC_KEY_RE = re.compile(
    r"(?P<anthropic>\bsk-ant-[A-Za-z0-9\-_]{20,})(?![A-Za-z0-9\-_])"
)

_HF_TOKEN_RE = re.compile(
    r"(?P<hf>\bhf_[A-Za-z0-9]{30,})(?![A-Za-z0-9])"
)

_GITLAB_TOKEN_RE = re.compile(
    r"(?P<gitlab>\bglpat-[A-Za-z0-9\-_]{20,})(?![A-Za-z0-9\-_])"
)

_NPM_TOKEN_RE = re.compile(
    r"(?P<npm>\bnpm_[A-Za-z0-9]{30,})(?![A-Za-z0-9])"
)

_PYPI_TOKEN_RE = re.compile(
    r"(?P<pypi>\bpypi-[A-Za-z0-9\-_]{30,})(?![A-Za-z0-9\-_])"
)

_TWILIO_KEY_RE = re.compile(
    r"(?P<twilio>\b(?:SK|AC)[0-9a-fA-F]{32})(?![0-9a-fA-F])"
)

_SENDGRID_KEY_RE = re.compile(
    r"(?P<sendgrid>\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{40,})(?![A-Za-z0-9\-_])"
)

_DISCORD_WEBHOOK_RE = re.compile(
    r"(?P<discord>https://discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9\-_]{60,})"
)

_GITHUB_TOKEN_RE = re.compile(
    r"(?P<ghtoken>(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}))"
    r"(?![A-Za-z0-9_])"
)

_SLACK_TOKEN_RE = re.compile(
    r"(?P<slack>(?:https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"
    r"|xox[bpras]-[A-Za-z0-9\-]{10,}))"
)

_STRIPE_KEY_RE = re.compile(
    r"(?P<stripe>\b(?:[rs]k|pk)_(?:live|test)_[A-Za-z0-9]{16,})(?![A-Za-z0-9])"
)

_OPENAI_KEY_RE = re.compile(
    r"(?P<openai>\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,})(?![A-Za-z0-9\-_])"
)

_GOOGLE_API_KEY_RE = re.compile(
    r"(?P<gkey>\bAIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9\-_])"
)

_AZURE_KEY_RE = re.compile(
    r"(?P<azkey>AccountKey=[A-Za-z0-9+/=]{40,})"
)

_DATABASE_URL_RE = re.compile(
    r"(?P<dburl>\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp[s]?)://[^\s'\"<>]+)",
    re.IGNORECASE,
)

_PRIVATE_KEY_RE = re.compile(
    r"(?P<pem>-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)"
)

# --- Network & geo --------------------------------------------------------

# MAC-48: six 2-hex groups. Guards exclude IPv6/time fragments.
_MAC_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:.\-])(?P<mac>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:.\-])"
)

# GPS pair: decimal lat/lon with range check in code. A decimal point in
# both parts is required so plain (id, count) pairs never match.
_COORD_CANDIDATE_RE = re.compile(
    r"(?<![\d.])(?P<coord>[+-]?(?:[1-8]?\d\.\d+|90\.0+)\s*[,;]\s*[+-]?(?:(?:1[0-7]\d|[1-9]?\d)\.\d+|180\.0+))(?![\d.])"
)

# SWIFT/BIC: 4-letter bank + 2-letter country + 2-alnum location +
# optional 3-char branch. Country validated against ISO 3166 in code.
_BIC_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9])(?P<bic>[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(?![A-Z0-9])"
)

# Context-gated IDs: the label carries the precision, the value is loose.
_DL_CONTEXT_RE = re.compile(
    r"(?i)\b(?:driver'?s?(?:\s+licen[sc]e)?|licen[sc]e|dl)"
    r"(?:\s*(?:no\.?|number|#))?\s*[:#\-]?\s*['\"]?(?P<dl>[A-Z0-9][A-Z0-9\- ]{4,19})['\"]?"
)

_HEALTH_CONTEXT_RE = re.compile(
    r"(?i)\b(?:member|policy|subscriber|patient|medicare|medicaid|health|insurance|group|rx)"
    r"(?:\s+(?:id|no\.?|number|#|card))?\s*[:#\-]?\s*['\"]?(?P<hi>[A-Z0-9][A-Z0-9\- ]{5,19})['\"]?"
)

# Label words that must never appear inside a captured loose value: when the
# label repeats ("health insurance member ID W123…") a naive match eats the
# label itself and the real value leaks through unmasked.
_DL_LABEL_WORDS = frozenset({"driver", "drivers", "license", "licence", "dl"})
_HEALTH_LABEL_WORDS = frozenset({"member", "policy", "subscriber", "patient",
                                 "medicare", "medicaid", "health", "insurance",
                                 "group", "rx"})


def _has_label_word(value: str, labels: frozenset) -> bool:
    """True when a whitespace-separated token of value is itself a label."""
    return any(tok in labels for tok in value.lower().split())


def _trim_trailing_words(value: str) -> str:
    """Drop trailing space-separated tokens that carry no digit.

    The loose ``[A-Z0-9\\- ]`` value class greedily absorbs the following
    prose word ("D1234567 suspended"); real multi-group IDs keep digits in
    every group, so digit-less tail tokens are prose, not ID.
    """
    toks = value.split(" ")
    while len(toks) > 1 and not re.search(r"\d", toks[-1]):
        toks.pop()
    return " ".join(toks)


# ICAO Doc 9303 MRZ lines: exactly 44 chars of A-Z/0-9/<.
_MRZ_LINE_RE = re.compile(r"(?m)^(?P<mrz>[A-Z0-9<]{44})$")


# ---------------------------------------------------------------------------
# Algorithmic validators
# ---------------------------------------------------------------------------

def is_valid_tr_national_id(value: str) -> bool:
    """Validate a Turkish National ID (T.C. Kimlik No).

    Rules (official algorithm):
      * 11 digits, first digit != 0.
      * 10th digit (Mod10): ((sum(odd positions 1,3,5,7,9) * 7)
        - sum(even positions 2,4,6,8)) mod 10.
      * 11th digit (Mod11): (sum of first 10 digits) mod 10.
      * 11th digit must also be even (a consequence of the checksum, but the
        spec commonly lists it; enforced implicitly by the Mod11 check —
        we check it explicitly for early rejection).

    >>> is_valid_tr_national_id("10000000146")
    True
    >>> is_valid_tr_national_id("12345678901")
    False
    """
    _m = _native()
    if _m is not None:
        try:
            return bool(_m.tr_national_id_valid(value))
        except Exception:
            pass
    digits_only = re.sub(r"\D", "", value)
    if len(digits_only) != 11 or digits_only[0] == "0":
        return False
    d = [int(c) for c in digits_only]
    odd_sum = d[0] + d[2] + d[4] + d[6] + d[8]
    even_sum = d[1] + d[3] + d[5] + d[7]
    if ((odd_sum * 7) - even_sum) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


def is_valid_luhn(value: str) -> bool:
    """Validate a credit-card number with the Luhn (Mod 10) algorithm.

    Accepts spaces/dashes (``"4539 1488 0343 6467"``). Requires 13–19 digits
    after stripping separators and rejects all-identical-digit sequences
    (e.g. ``"0000000000000"``) which pass Luhn but are never real PANs.

    >>> is_valid_luhn("4539148803436467")
    True
    >>> is_valid_luhn("4539148803436468")
    False
    """
    _m = _native()
    if _m is not None:
        try:
            return bool(_m.luhn_valid(value))
        except Exception:
            pass
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:  # degenerate sequence, e.g. all zeros
        return False
    total = 0
    # Process right-to-left, doubling every second digit.
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# International validators: PESEL (PL), SSN (US), NIF/NIE (ES), IBAN
# ---------------------------------------------------------------------------

_PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)


def extract_pesel_dob(value: str) -> date | None:
    """Extract the date of birth encoded in a PESEL number.

    Digits 1-6 hold YYMMDD where the month encodes the century: +0 for the
    1900s, +20 (2000s), +40 (2100s), +60 (2200s), +80 (1800s). Returns
    ``None`` for out-of-range months or impossible calendar dates (e.g. Feb 30,
    caught via :class:`datetime.date`). Used by :func:`is_valid_pesel` as a
    DOB-range filter against random 11-digit runs.

    >>> extract_pesel_dob("44051401359")
    datetime.date(1944, 5, 14)
    >>> extract_pesel_dob("02210100000")
    datetime.date(2002, 1, 1)
    >>> extract_pesel_dob("44330100000") is None  # month 33: no century
    True
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or not digits.isdigit():
        return None
    yy, mm, dd = int(digits[0:2]), int(digits[2:4]), int(digits[4:6])
    if 1 <= mm <= 12:
        century = 1900
    elif 21 <= mm <= 32:
        century, mm = 2000, mm - 20
    elif 41 <= mm <= 52:
        century, mm = 2100, mm - 40
    elif 61 <= mm <= 72:
        century, mm = 2200, mm - 60
    elif 81 <= mm <= 92:
        century, mm = 1800, mm - 80
    else:
        return None
    try:
        return date(century + yy, mm, dd)
    except ValueError:
        return None


def is_valid_pesel(value: str) -> bool:
    """Validate a Polish PESEL number (11 digits, weighted Mod 10 + DOB).

    Checksum: ``sum(d[i] * w[i]) mod 10`` over the first 10 digits with
    weights ``1,3,7,9,1,3,7,9,1,3``; the control digit is ``(10 - sum) mod 10``.
    Numbers whose first six digits do not encode a real date are rejected.

    >>> is_valid_pesel("44051401359")
    True
    >>> is_valid_pesel("44051401358")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or not digits.isdigit():
        return False
    if extract_pesel_dob(digits) is None:
        return False
    checksum = sum(int(d) * w for d, w in zip(digits[:10], _PESEL_WEIGHTS, strict=False)) % 10
    return (10 - checksum) % 10 == int(digits[10])


def is_valid_ssn(value: str) -> bool:
    """Validate a US Social Security Number (AAA-GG-SSSS) against SSA rules.

    Rejects unknown area numbers (``000``, ``666``, ``900-999``), group
    ``00`` and serial ``0000``. Separators are ignored, so spaced and dashed
    forms validate identically. (Whether an SSN was ever *issued* cannot be
    determined locally — this is a format/validity gate, not issuance proof.)

    >>> is_valid_ssn("078-05-1120")
    True
    >>> is_valid_ssn("666-12-3456")
    False
    >>> is_valid_ssn("900-12-3456")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area[0] == "9":  # 900-999 never allocated
        return False
    return not (group == "00" or serial == "0000")


_ES_CONTROL_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"  # index = number mod 23
_NIE_PREFIX_DIGIT = {"X": "0", "Y": "1", "Z": "2"}


def _es_control_letter(number: int) -> str:
    """Spanish Mod 23 control letter shared by NIF and NIE."""
    return _ES_CONTROL_LETTERS[number % 23]


def is_valid_nif(value: str) -> bool:
    """Validate a Spanish NIF (8 digits + Mod 23 control letter).

    >>> is_valid_nif("12345678Z")
    True
    >>> is_valid_nif("12345678A")
    False
    """
    v = value.strip().upper()
    if len(v) != 9 or not v[:8].isdigit() or not v[8].isalpha():
        return False
    return _es_control_letter(int(v[:8])) == v[8]


def is_valid_nie(value: str) -> bool:
    """Validate a Spanish NIE (X/Y/Z + 7 digits + Mod 23 control letter).

    The leading letter maps to a digit (X→0, Y→1, Z→2); the resulting
    8-digit number follows the same Mod 23 rule as the NIF.

    >>> is_valid_nie("X1234567L")
    True
    >>> is_valid_nie("X1234567A")
    False
    """
    v = value.strip().upper()
    if len(v) != 9 or v[0] not in _NIE_PREFIX_DIGIT:
        return False
    if not v[1:8].isdigit() or not v[8].isalpha():
        return False
    return _es_control_letter(int(_NIE_PREFIX_DIGIT[v[0]] + v[1:8])) == v[8]


# Official IBAN lengths for common countries (ISO 13616 registry, Aug 2024).
# Countries missing here fall back to the generic 15-32 range check below —
# the Mod 97 test still applies, so detection quality barely degrades.
_IBAN_COUNTRY_LENGTHS: dict[str, int] = {
    "AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BY": 28, "BE": 16,
    "BA": 20, "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24,
    "DK": 18, "DJ": 27, "DO": 28, "EG": 29, "SV": 32, "FO": 18, "FI": 18,
    "FR": 27, "GE": 22, "DE": 22, "GI": 23, "GR": 27, "GL": 18, "GT": 28,
    "HU": 28, "IQ": 23, "IS": 26, "IE": 22, "IL": 23, "IT": 27, "JO": 30,
    "KZ": 20, "XK": 20, "KW": 30, "LV": 21, "LB": 28, "LI": 21, "LT": 20,
    "LU": 20, "MK": 19, "MT": 31, "MR": 27, "MU": 30, "MC": 27, "MD": 24,
    "ME": 22, "NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28, "PT": 25,
    "QA": 29, "RO": 24, "SM": 27, "SA": 24, "RS": 22, "SK": 24, "SI": 19,
    "ES": 24, "SD": 18, "SE": 24, "CH": 21, "TL": 19, "TN": 24, "TR": 26,
    "UA": 29, "UG": 28, "GB": 22, "DZ": 26, "AO": 25, "BF": 28, "BJ": 28,
    "CM": 27, "CV": 25, "IR": 22, "MG": 27, "ML": 28, "MZ": 25, "SN": 28,
}


def _iban_mod97(compact: str) -> int:
    """ISO 7064 Mod 97 remainder over a spaceless, uppercased IBAN."""
    _m = _native()
    if _m is not None:
        try:
            return int(_m.iban_mod97(compact))
        except Exception:
            pass
    rearranged = compact[4:] + compact[:4]  # move country+check to the end
    remainder = 0
    for ch in rearranged:
        block = str(ord(ch) - 55) if "A" <= ch <= "Z" else ch  # A=10 … Z=35
        for digit in block:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder


def is_valid_iban(value: str) -> bool:
    """Validate an IBAN (ISO 13616 / ISO 7064 Mod 97-10).

    Accepts spaced print format and compact form, any letter case. Checks
    structure (2 letters + 2 digits + BBAN), per-country length where known
    (15-32 fallback otherwise), and requires ``mod97 == 1``.

    >>> is_valid_iban("DE89370400440532013000")
    True
    >>> is_valid_iban("TR330006100519786457841326")
    True
    >>> is_valid_iban("DE89370400440532013001")
    False
    """
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,28}", compact):
        return False
    expected = _IBAN_COUNTRY_LENGTHS.get(compact[:2])
    if expected is not None:
        if len(compact) != expected:
            return False
    elif not 15 <= len(compact) <= 32:
        return False
    return _iban_mod97(compact) == 1


# ---------------------------------------------------------------------------
# Global validators: NINo (GB), NIR (FR), Codice Fiscale (IT),
# CPF (BR), Steuerliche Identifikationsnummer (DE)
# ---------------------------------------------------------------------------

_NINO_FORBIDDEN_PREFIXES = frozenset({"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"})


def is_valid_nino(value: str) -> bool:
    """Validate a UK National Insurance number.

    Format: 2 prefix letters + 6 digits + suffix A-D. The first letter is
    never D/F/I/Q/U/V, the second never D/F/I/O/Q/U/V, and the prefixes
    BG/GB/KN/NK/NT/TN/ZZ were never issued.

    >>> is_valid_nino("AB123456C")
    True
    >>> is_valid_nino("DA123456C")
    False
    """
    v = re.sub(r"\s+", "", value).upper()
    m = re.fullmatch(r"([A-CEGHJ-PR-TW-Z]{2})(\d{6})([A-D])", v)
    if not m:
        return False
    prefix = m.group(1)
    if prefix in _NINO_FORBIDDEN_PREFIXES:
        return False
    return prefix[1] not in "DFIOQUV"


def is_valid_nir(value: str) -> bool:
    """Validate a French NIR / INSEE number (15 chars, Mod 97 key).

    Structure: gender(1/2) + year(2) + month(01-12) + dept(2 digits or
    Corsican 2A/2B) + serial(6 digits) + key(2 digits). Key rule:
    ``key = 97 - (first13 mod 97)`` with 2A→19 / 2B→18 substitution.

    >>> is_valid_nir("184127500512135")
    True
    >>> is_valid_nir("184127500512136")
    False
    """
    compact = re.sub(r"\s+", "", value).upper()
    if len(compact) != 15:
        return False
    if compact[0] not in "12":
        return False
    if not compact[1:3].isdigit():
        return False
    if not 1 <= int(compact[3:5]) <= 12:
        return False
    dept = compact[5:7]
    if not (dept.isdigit() or dept in ("2A", "2B")):
        return False
    if not compact[7:13].isdigit() or not compact[13:].isdigit():
        return False
    keyed = compact[:13].replace("2A", "19").replace("2B", "18")
    return 97 - (int(keyed) % 97) == int(compact[13:])


_FISCAL_MONTHS = "ABCDEHLMPRST"
_FISCAL_ODD_MAP = {
    "0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15, "7": 17,
    "8": 19, "9": 21, "A": 1, "B": 0, "C": 5, "D": 7, "E": 9, "F": 13,
    "G": 15, "H": 17, "I": 19, "J": 21, "K": 2, "L": 4, "M": 18, "N": 20,
    "O": 11, "P": 3, "Q": 6, "R": 8, "S": 12, "T": 14, "U": 16, "V": 10,
    "W": 22, "X": 25, "Y": 24, "Z": 23,
}


def _fiscal_even_value(ch: str) -> int:
    """Even-position value: digits keep face value, letters A=0 … Z=25."""
    if ch.isdigit():
        return int(ch)
    return ord(ch) - 65


def is_valid_fiscal(value: str) -> bool:
    """Validate an Italian Codice Fiscale (16 chars, check letter).

    Checks structure (month letter, day 01-31 / 41-71 for women) and the
    check letter: odd positions use the disparity table, even positions
    face value; ``sum % 26`` maps to A-Z.

    >>> is_valid_fiscal("RSSMRA80A01H501U")
    True
    >>> is_valid_fiscal("RSSMRA80A01H501A")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]", v):
        return False
    if v[8] not in _FISCAL_MONTHS:
        return False
    day = int(v[9:11])
    if not (1 <= day <= 31 or 41 <= day <= 71):
        return False
    total = 0
    for i, ch in enumerate(v[:15]):
        if i % 2 == 0:  # 1-indexed odd position
            total += _FISCAL_ODD_MAP[ch]
        else:
            total += _fiscal_even_value(ch)
    return chr(65 + total % 26) == v[15]


def is_valid_cpf(value: str) -> bool:
    """Validate a Brazilian CPF (11 digits, two Mod 11 check digits).

    Accepts plain (``11144477735``) and formatted (``111.444.777-35``)
    forms. Rejects all-identical-digit sequences.

    >>> is_valid_cpf("111.444.777-35")
    True
    >>> is_valid_cpf("111.444.777-36")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    d = [int(c) for c in digits]
    for length in (9, 10):
        base = d[:length]
        weights = range(length + 1, 1, -1)
        remainder = sum(x * w for x, w in zip(base, weights, strict=False)) % 11
        check = 0 if remainder < 2 else 11 - remainder
        if check != d[length]:
            return False
    return True


def is_valid_de_idnr(value: str) -> bool:
    """Validate a German Steuerliche Identifikationsnummer (ISO 7064 MOD 11,10).

    11 digits, first digit != 0. Checksum: ``p = 10``; for each of the
    first 10 digits ``s = (d + p) mod 10`` (0 becomes 10), ``p = (2*s)
    mod 11``; check digit is ``11 - p`` (10 becomes 0).

    >>> is_valid_de_idnr("86095742719")
    True
    >>> is_valid_de_idnr("86095742718")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or not digits.isdigit() or digits[0] == "0":
        return False
    if len(set(digits)) == 1:
        return False
    p = 10
    for ch in digits[:10]:
        s = (int(ch) + p) % 10
        if s == 0:
            s = 10
        p = (2 * s) % 11
    check = 0 if p == 1 else 11 - p
    return check == int(digits[10])


# ---------------------------------------------------------------------------
# EU validators: BSN (NL), National Number (BE), HETU (FI),
# Personnummer (SE), Fødselsnummer (NO), NIF (PT), CNP (RO), AFM (GR)
# ---------------------------------------------------------------------------

def is_valid_bsn(value: str) -> bool:
    """Validate a Dutch BSN (9 digits, elfproef / 11-proof).

    ``9·d1 + 8·d2 + … + 2·d8 − d9`` must be a multiple of 11.
    Leading zeros allowed; all-identical runs rejected.

    >>> is_valid_bsn("123456782")
    True
    >>> is_valid_bsn("123456783")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    d = [int(c) for c in digits]
    return (sum(x * (9 - i) for i, x in enumerate(d[:8])) - d[8]) % 11 == 0


def is_valid_be_national(value: str) -> bool:
    """Validate a Belgian National Number (11 digits, Mod 97).

    Structure YYMMDD-XXX-CC (separators optional). Check rule:
    ``CC = 97 − (first9 mod 97)`` (97 when the remainder is 0); numbers
    issued from 2000 on use ``2_000_000_000 + first9`` before the Mod 97.

    >>> is_valid_be_national("93051822361")
    True
    >>> is_valid_be_national("93051822365")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    yy, mm, dd = int(digits[0:2]), int(digits[2:4]), int(digits[4:6])
    if not 1 <= mm <= 12 or not 1 <= dd <= 31:
        return False
    try:
        date(1900 + yy, mm, dd)
    except ValueError:
        try:
            date(2000 + yy, mm, dd)
        except ValueError:
            return False
    first9, want = int(digits[:9]), int(digits[9:])
    for base in (first9, 2000000000 + first9):
        r = base % 97
        if (97 if r == 0 else 97 - r) == want:
            return True
    return False


_HETU_TABLE = "0123456789ABCDEFHJKLMNPRSTUVWXY"
_HETU_CENTURY = {"+": 1800, "-": 1900, "A": 2000}


def is_valid_hetu(value: str) -> bool:
    """Validate a Finnish HETU (DDMMYY + century sign + Mod 31 check char).

    Century sign: ``+`` 1800s, ``-`` 1900s, ``A`` 2000s. Check char is
    ``TABLE[(DDMMYYIII) mod 31]`` over ``"0123456789ABCDEFHJKLMNPRSTUVWXY"``.

    >>> is_valid_hetu("131052-308T")
    True
    >>> is_valid_hetu("131052-308U")
    False
    """
    v = value.strip().upper()
    m = re.fullmatch(r"(\d{6})([+\-A])(\d{3})([0-9A-Z])", v)
    if not m:
        return False
    dd, mm, yy = int(m.group(1)[0:2]), int(m.group(1)[2:4]), int(m.group(1)[4:6])
    try:
        date(_HETU_CENTURY[m.group(2)] + yy, mm, dd)
    except ValueError:
        return False
    if not 2 <= int(m.group(3)) <= 999:
        return False
    return _HETU_TABLE[int(m.group(1) + m.group(3)) % 31] == m.group(4)


def _luhn_digits(digits: str) -> bool:
    """Luhn check over a pure digit string (shared by SE/IMEI/etc)."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def is_valid_se_pnr(value: str) -> bool:
    """Validate a Swedish Personnummer (10/12 digits, Luhn over 10).

    Accepts ``YYMMDD-NNNN``, ``YYMMDDNNNN``, ``YYYYMMDDNNNN`` and the
    ``+`` separator for ages 100+. Samordningsnummer (day + 60) accepted.

    >>> is_valid_se_pnr("1212121212")
    True
    >>> is_valid_se_pnr("121212-1212")
    True
    >>> is_valid_se_pnr("1212121213")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) == 12:
        if digits[:2] not in ("18", "19", "20"):
            return False
        digits = digits[2:]
    if len(digits) != 10 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    mm, dd = int(digits[2:4]), int(digits[4:6])
    day = dd - 60 if dd > 60 else dd
    if not 1 <= mm <= 12 or not 1 <= day <= 31:
        return False
    if mm == 2 and day > 29:
        return False
    if mm in (4, 6, 9, 11) and day > 30:
        return False
    return _luhn_digits(digits)


def is_valid_no_fnr(value: str) -> bool:
    """Validate a Norwegian Fødselsnummer (11 digits, double Mod 11).

    ``k1 = 11 − (3d1+7d2+6d3+1d4+8d5+9d6+4d7+5d8+2d9 mod 11)`` (11→0,
    10→invalid), then the same over d1..d9,k1 with weights 5,4,3,2,7,6,
    5,4,3,2 for ``k2``.

    >>> is_valid_no_fnr("01010112377")
    True
    >>> is_valid_no_fnr("01010112378")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    dd, mm = int(digits[0:2]), int(digits[2:4])
    if not 1 <= mm <= 12 or not 1 <= dd <= 31:
        return False
    if mm == 2 and dd > 29:
        return False
    if mm in (4, 6, 9, 11) and dd > 30:
        return False
    d = [int(c) for c in digits]
    k1 = 11 - ((3 * d[0] + 7 * d[1] + 6 * d[2] + d[3] + 8 * d[4]
                + 9 * d[5] + 4 * d[6] + 5 * d[7] + 2 * d[8]) % 11)
    if k1 == 11:
        k1 = 0
    if k1 == 10 or k1 != d[9]:
        return False
    k2 = 11 - ((5 * d[0] + 4 * d[1] + 3 * d[2] + 2 * d[3] + 7 * d[4]
                + 6 * d[5] + 5 * d[6] + 4 * d[7] + 3 * d[8] + 2 * d[9]) % 11)
    if k2 == 11:
        k2 = 0
    return k2 != 10 and k2 == d[10]


def is_valid_pt_nif(value: str) -> bool:
    """Validate a Portuguese NIF (9 digits, Mod 11).

    Weights 9..2 over the first 8 digits; check is 0 when the remainder
    is 0/1, else ``11 − remainder``.

    >>> is_valid_pt_nif("123456789")
    True
    >>> is_valid_pt_nif("123456788")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit() or digits[0] == "0":
        return False
    if len(set(digits)) == 1:
        return False
    d = [int(c) for c in digits]
    r = sum(x * (9 - i) for i, x in enumerate(d[:8])) % 11
    return (0 if r < 2 else 11 - r) == d[8]


def is_valid_ro_cnp(value: str) -> bool:
    """Validate a Romanian CNP (13 digits, Mod 11 with 10→1).

    Leading digit encodes sex/century (1-9); YYMMDD must be a real date,
    county 01-52, serial 001-999. Weights 2,7,9,1,4,6,3,5,8,2,7,9.

    >>> is_valid_ro_cnp("1900101400012")
    True
    >>> is_valid_ro_cnp("1900101400013")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13 or not digits.isdigit() or digits[0] == "0":
        return False
    if len(set(digits)) == 1:
        return False
    s = int(digits[0])
    century = {1: 1900, 2: 1900, 3: 1800, 4: 1800, 5: 2000,
               6: 2000, 7: 1900, 8: 1900, 9: 1800}[s]
    try:
        date(century + int(digits[1:3]), int(digits[3:5]), int(digits[5:7]))
    except ValueError:
        return False
    if not 1 <= int(digits[7:9]) <= 52:
        return False
    if not 1 <= int(digits[9:12]) <= 999:
        return False
    weights = (2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9)
    r = sum(int(c) * w for c, w in zip(digits[:12], weights, strict=False)) % 11
    return (1 if r == 10 else r) == int(digits[12])


def is_valid_gr_afm(value: str) -> bool:
    """Validate a Greek AFM (9 digits, powers-of-two Mod 11/10).

    ``(Σ d[i]·2^(8−i) mod 11) mod 10`` over the first 8 digits.

    >>> is_valid_gr_afm("123456783")
    True
    >>> is_valid_gr_afm("123456784")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit() or digits[0] == "0":
        return False
    if len(set(digits)) == 1:
        return False
    d = [int(c) for c in digits]
    return (sum(x * 2 ** (8 - i) for i, x in enumerate(d[:8])) % 11) % 10 == d[8]


# ---------------------------------------------------------------------------
# Financial validators: ABA (US), ITIN (US), ISIN, SEDOL, ABN (AU)
# (IFSC (IN) is shape-specific and needs no checksum — direct regex above.)
# ---------------------------------------------------------------------------

_ABA_DISTRICTS = frozenset(
    ["00"] + [f"{n:02d}" for n in list(range(1, 13)) + list(range(21, 33))
              + list(range(61, 73))] + ["80"]
)


def is_valid_aba(value: str) -> bool:
    """Validate a US ABA routing number (9 digits, 3-7-1 Mod 10).

    First two digits must be a real district (00-12, 21-32, 61-72, 80);
    ``(3·(d1+d4+d7) + 7·(d2+d5+d8) + (d3+d6+d9)) mod 10 == 0``.

    >>> is_valid_aba("021000021")
    True
    >>> is_valid_aba("021000022")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    if digits[:2] not in _ABA_DISTRICTS:
        return False
    d = [int(c) for c in digits]
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7])
            + (d[2] + d[5] + d[8])) % 10 == 0


def is_valid_itin(value: str) -> bool:
    """Validate a US ITIN (9XX-7X/8X-XXXX, rule-based, no checksum).

    Area is always 9XX; the middle group is 70-88, 90-92 or 94-99
    (ranges the SSA never issues as SSNs).

    >>> is_valid_itin("900-70-1234")
    True
    >>> is_valid_itin("900-69-1234")
    False
    >>> is_valid_itin("078-05-1120")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    if not digits.startswith("9"):
        return False
    middle = int(digits[3:5])
    return (70 <= middle <= 88) or middle in (90, 91, 92) or 94 <= middle <= 99


def is_valid_isin(value: str) -> bool:
    """Validate an ISIN (2 letters + 9 alnum + Luhn check digit).

    Letters convert A=10 … Z=35, then plain Luhn over the digit string.

    >>> is_valid_isin("US0378331005")
    True
    >>> is_valid_isin("US0378331006")
    False
    """
    v = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}[A-Z0-9]{9}\d", v):
        return False
    digits = "".join(str(ord(c) - 55) if "A" <= c <= "Z" else c for c in v)
    return _luhn_digits(digits)


def is_valid_sedol(value: str) -> bool:
    """Validate a SEDOL (7 chars, weighted Mod 10, no vowels issued).

    Weights 1,3,1,7,3,9,1; at least one digit required so English words
    never match even when the checksum accidentally passes.

    >>> is_valid_sedol("0263494")
    True
    >>> is_valid_sedol("0263495")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{7}", v):
        return False
    if not re.search(r"\d", v) or re.search(r"[AEIOU]", v):
        return False
    weights = (1, 3, 1, 7, 3, 9, 1)
    vals = [(ord(c) - 55) if c.isalpha() else int(c) for c in v]
    return sum(x * w for x, w in zip(vals, weights, strict=False)) % 10 == 0


_ABN_WEIGHTS = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)


def is_valid_abn(value: str) -> bool:
    """Validate an Australian ABN (11 digits, weighted Mod 89).

    Subtract 1 from the first digit, then ``Σ d[i]·w[i] mod 89 == 0``
    with weights 10,1,3,5,7,9,11,13,15,17,19.

    >>> is_valid_abn("51824753556")
    True
    >>> is_valid_abn("51824753557")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or not digits.isdigit() or digits[0] == "0":
        return False
    if len(set(digits)) == 1:
        return False
    d = [int(c) for c in digits]
    return ((d[0] - 1) * 10 + sum(x * w for x, w in zip(d[1:], _ABN_WEIGHTS[1:], strict=False))
            ) % 89 == 0


# ---------------------------------------------------------------------------
# APAC/MEA + device validators: CN ID, KR RRN, SG NRIC, IL ID, ZA ID,
# TH ID, TW ID, HK ID, JP My Number, IMEI, VIN
# ---------------------------------------------------------------------------

_CN_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_CHECK_MAP = "10X98765432"


def is_valid_cn_id(value: str) -> bool:
    """Validate a Chinese Resident Identity Card number (ISO 7064 MOD 11-2).

    17 digits + check (digit or X); digits 7-12 must be a real YYYYMMDD
    birth date. Check: ``MAP[Σ d[i]·w[i] mod 11]`` with weights
    7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2 and map ``"10X98765432"``.

    >>> is_valid_cn_id("11010519491231002X")
    True
    >>> is_valid_cn_id("110105194912310021")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"\d{17}[0-9X]", v):
        return False
    if len(set(v)) == 1:
        return False
    try:
        date(int(v[6:10]), int(v[10:12]), int(v[12:14]))
    except ValueError:
        return False
    r = sum(int(c) * w for c, w in zip(v[:17], _CN_WEIGHTS, strict=False)) % 11
    return _CN_CHECK_MAP[r] == v[17]


_KR_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)


def is_valid_kr_rrn(value: str) -> bool:
    """Validate a Korean RRN (13 digits, Mod 11).

    Layout YYMMDD-SBBBBNC: YYMMDD must be a real date (century from the
    gender digit: 1/2/5/6 → 1900s, 3/4/7/8 → 2000s). Check:
    ``(11 − Σ d[i]·w[i] mod 11) mod 10`` with weights
    2,3,4,5,6,7,8,9,2,3,4,5 over the first 12 digits.

    >>> is_valid_kr_rrn("9001011234568")
    True
    >>> is_valid_kr_rrn("9001011234567")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    gender = int(digits[6])
    if gender not in (1, 2, 3, 4, 5, 6, 7, 8):
        return False
    century = 1900 if gender in (1, 2, 5, 6) else 2000
    try:
        date(century + int(digits[0:2]), int(digits[2:4]), int(digits[4:6]))
    except ValueError:
        return False
    r = sum(int(c) * w for c, w in zip(digits[:12], _KR_WEIGHTS, strict=False)) % 11
    return (11 - r) % 10 == int(digits[12])


_SG_WEIGHTS = (2, 7, 6, 5, 4, 3, 2)
_SG_TABLE_ST = "JZIHGFEDCBA"
_SG_TABLE_FG = "XWUTRQPNMLK"


def is_valid_sg_nric(value: str) -> bool:
    """Validate a Singapore NRIC/FIN (letter + 7 digits + Mod-11 letter).

    Series S/T use table ``"JZIHGFEDCBA"``, F/G use ``"XWUTRQPNMLK"``;
    weights 2,7,6,5,4,3,2 with a +4 offset for T and G. The M series
    (2022+) is excluded — its rule is not publicly stable.

    >>> is_valid_sg_nric("S1234567D")
    True
    >>> is_valid_sg_nric("T1234567J")
    True
    >>> is_valid_sg_nric("F1234567N")
    True
    >>> is_valid_sg_nric("G1234567X")
    True
    >>> is_valid_sg_nric("S1234567A")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[STFG]\d{7}[A-Z]", v):
        return False
    series, check = v[0], v[8]
    total = sum(int(c) * w for c, w in zip(v[1:8], _SG_WEIGHTS, strict=False))
    if series in ("T", "G"):
        total += 4
    table = _SG_TABLE_ST if series in ("S", "T") else _SG_TABLE_FG
    return table[total % 11] == check


def is_valid_il_id(value: str) -> bool:
    """Validate an Israeli ID number (up to 9 digits, Luhn, zero-padded).

    >>> is_valid_il_id("02498327")
    True
    >>> is_valid_il_id("02498328")
    False
    """
    digits = re.sub(r"\D", "", value)
    if not 1 <= len(digits) <= 9 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    return _luhn_digits(digits.zfill(9))


def is_valid_za_id(value: str) -> bool:
    """Validate a South African ID number (13 digits, Luhn + date).

    Layout YYMMDD SSSS C A C: birth date, sequence, citizenship (0/1),
    race-code legacy digit, Luhn check.

    >>> is_valid_za_id("8001015009087")
    True
    >>> is_valid_za_id("8001015009088")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    try:
        date(1900 + int(digits[0:2]), int(digits[2:4]), int(digits[4:6]))
    except ValueError:
        try:
            date(2000 + int(digits[0:2]), int(digits[2:4]), int(digits[4:6]))
        except ValueError:
            return False
    if digits[10] not in "01":
        return False
    return _luhn_digits(digits)


def is_valid_th_id(value: str) -> bool:
    """Validate a Thai ID number (13 digits, Mod 11, 10→last-digit rule).

    First digit 1-8 (person category); ``(11 − Σ d[i]·(13−i) mod 11) mod 10``.

    >>> is_valid_th_id("1234567890121")
    True
    >>> is_valid_th_id("1234567890122")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 13 or not digits.isdigit() or digits[0] not in "12345678":
        return False
    if len(set(digits)) == 1:
        return False
    r = sum(int(c) * (13 - i) for i, c in enumerate(digits[:12])) % 11
    return (11 - r) % 10 == int(digits[12])


_TW_MAP = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16,
    "H": 17, "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22,
    "O": 35, "P": 23, "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28,
    "V": 29, "W": 30, "X": 31, "Y": 32, "Z": 33,
}


def is_valid_tw_id(value: str) -> bool:
    """Validate a Taiwan ID (letter + 9 digits, weighted Mod 10).

    The leading letter maps to two digits (A=10 … Z=33, I/O special);
    ``(10 − total mod 10) mod 10`` with weights 1,9,8,7,6,5,4,3,2,1,1.

    >>> is_valid_tw_id("A123456789")
    True
    >>> is_valid_tw_id("A123456788")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[A-Z]\d{9}", v) or v[0] not in _TW_MAP:
        return False
    a = _TW_MAP[v[0]]
    total = (a // 10) * 1 + (a % 10) * 9
    total += sum(int(c) * (8 - i) for i, c in enumerate(v[1:9]))
    return (10 - total % 10) % 10 == int(v[9])


def is_valid_hk_id(value: str) -> bool:
    """Validate a Hong Kong ID (1-2 letters + 6 digits + Mod-11 check).

    Weights 9..1 (two letters) or 8..1 (one letter); letters A=10 … Z=35
    and check ``A`` counts as 10. Check digit in optional parentheses.

    >>> is_valid_hk_id("A123456(8)")
    True
    >>> is_valid_hk_id("A123456(7)")
    False
    """
    v = re.sub(r"[\s()]", "", value.strip().upper())
    m = re.fullmatch(r"([A-Z]{1,2})(\d{6})([0-9A])", v)
    if not m:
        return False
    letters, check = m.group(1), (10 if m.group(3) == "A" else int(m.group(3)))
    vals = [ord(c) - 55 for c in letters] + [int(c) for c in m.group(2)]
    weights = list(range(9, 9 - len(vals), -1)) if len(letters) == 2 \
        else list(range(8, 8 - len(vals), -1))
    return (sum(x * w for x, w in zip(vals, weights, strict=False)) + check) % 11 == 0


_JP_WEIGHTS = (6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2)


def is_valid_jp_number(value: str) -> bool:
    """Validate a Japanese My Number (12 digits, Mod 11).

    ``Q = Σ d[i]·w[i] mod 11`` with weights 6,5,4,3,2,7,6,5,4,3,2;
    check is 0 when Q ≤ 1, else ``11 − Q``.

    >>> is_valid_jp_number("123456789018")
    True
    >>> is_valid_jp_number("123456789019")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    r = sum(int(c) * w for c, w in zip(digits[:11], _JP_WEIGHTS, strict=False)) % 11
    return (0 if r <= 1 else 11 - r) == int(digits[11])


def is_valid_imei(value: str) -> bool:
    """Validate an IMEI (15 digits, Luhn).

    >>> is_valid_imei("490154203237518")
    True
    >>> is_valid_imei("490154203237519")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 15 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    return _luhn_digits(digits)


_VIN_TRANSLIT = {
    **{str(n): n for n in range(10)},
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def is_valid_vin(value: str) -> bool:
    """Validate a VIN (17 chars, transliterated Mod 11 at position 9).

    Letters I/O/Q are never used; position 9 is the check (10 → ``X``).

    >>> is_valid_vin("1HGCM82633A004352")
    True
    >>> is_valid_vin("1HGCM82634A004352")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", v):
        return False
    r = sum(_VIN_TRANSLIT[c] * w for c, w in zip(v, _VIN_WEIGHTS, strict=False)) % 11
    return ("X" if r == 10 else str(r)) == v[8]


# ---------------------------------------------------------------------------
# Health + crypto validators: DEA (US), MBI (US), BTC, ETH
# ---------------------------------------------------------------------------

_DEA_FIRST_LETTERS = frozenset("ABCDEFGHJKLMPRSTUX")
_MBI_FORBIDDEN = frozenset("SLOIBZ")


def is_valid_dea(value: str) -> bool:
    """Validate a US DEA number (2 letters + 7 digits, summed check).

    First letter is the registrant class; check digit is the ones digit
    of ``(d1+d3+d5) + 2·(d2+d4+d6)``.

    >>> is_valid_dea("AB1234563")
    True
    >>> is_valid_dea("AB1234564")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}\d{7}", v):
        return False
    if v[0] not in _DEA_FIRST_LETTERS:
        return False
    d = [int(c) for c in v[2:]]
    return (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 == d[6]


def is_valid_mbi(value: str) -> bool:
    """Validate a US Medicare MBI (11 chars, strict positional classes).

    Layout N-A-AN-N-A-AN-N-A-AN-N-N; letters S/L/O/I/B/Z are never used.
    There is no checksum — the shape plus exclusions carry the precision.

    >>> is_valid_mbi("1EG4-TE5-MK73")
    True
    >>> is_valid_mbi("1EG4TE5MK73")
    True
    >>> is_valid_mbi("1SG4-TE5-MK73")
    False
    """
    v = re.sub(r"[\s-]", "", value.strip().upper())
    if len(v) != 11:
        return False
    classes = ("N", "A", "AN", "N", "A", "AN", "N", "A", "AN", "N", "N")
    for ch, kind in zip(v, classes, strict=False):
        if kind == "N" and not ch.isdigit():
            return False
        if kind == "A" and not (ch.isalpha() and ch not in _MBI_FORBIDDEN):
            return False
        if kind == "AN" and not (ch.isalnum() and ch not in _MBI_FORBIDDEN):
            return False
    return True


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(s: str) -> bytes | None:
    """Decode Base58 (Bitcoin alphabet) to bytes; None on bad chars."""
    num = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            return None
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8 or 1, "big")
    pad = len(s) - len(s.lstrip("1"))  # leading '1's are zero bytes
    return b"\x00" * pad + raw


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_valid(addr: str) -> bool:
    """BIP-173 bech32 checksum over a lowercase bc1 address."""
    v = addr.lower()
    if not v.startswith("bc1") or not re.fullmatch(r"[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+", v[3:]):
        return False
    hrp = "bc"
    values = [_BECH32_CHARSET.find(c) for c in v[3:]]
    chk = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + values
    GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    polymod = 1
    for p in chk:
        b = polymod >> 25
        polymod = ((polymod & 0x1FFFFFF) << 5) ^ p
        for i in range(5):
            if (b >> i) & 1:
                polymod ^= GEN[i]
    return polymod == 1


def is_valid_btc(value: str) -> bool:
    """Validate a Bitcoin address (Base58Check or bech32, real checksums).

    Base58 ``1…``/``3…``: payload's double-SHA256 first 4 bytes must equal
    the trailing 4; ``bc1…``: BIP-173 polymod must be 1. Stdlib only.

    >>> is_valid_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    True
    >>> is_valid_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    False
    >>> is_valid_btc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    True
    """
    v = value.strip()
    if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", v):
        raw = _base58_decode(v)
        if raw is None or len(raw) < 5:
            return False
        payload, check = raw[:-4], raw[-4:]
        return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == check
    if v[:3].lower() == "bc1":
        return _bech32_valid(v)
    return False


def is_valid_eth(value: str) -> bool:
    """Validate an Ethereum address shape (0x + 40 hex, no checksum).

    Full EIP-55 validation needs Keccak-256, which is not in the stdlib,
    so this is a shape gate at reduced confidence — the trade-off is
    documented on the detector.

    >>> is_valid_eth("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
    True
    >>> is_valid_eth("0x742d35Cc6634C0532925a3b844Bc454e4438f44")
    False
    """
    return re.fullmatch(r"0x[0-9a-fA-F]{40}", value.strip()) is not None


def is_valid_eth_eip55(value: str) -> bool:
    """Validate EIP-55 checksummed address (requires Keccak-256).

    All-lowercase / all-uppercase (non-checksummed) forms return True when
    the shape holds — EIP-55 explicitly treats them as valid non-checksummed.
    Mixed-case must match the Keccak-derived capitalization. Returns False
    when shape fails or when keccak backend is missing and case is mixed
    (cannot verify -> conservative False; caller should fall back to shape).

    >>> is_valid_eth_eip55("0x52908400098527886E0F7030069857D2E цифр".strip())
    False
    """
    v = value.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", v) is None:
        return False
    body = v[2:]
    if body == body.lower() or body == body.upper():
        return True
    if _keccak256 is None:
        return False
    try:
        digest = _keccak256(body.lower().encode("ascii")).hexdigest()
    except Exception:
        return False
    for i, ch in enumerate(body):
        if ch.isalpha():
            should_upper = int(digest[i], 16) >= 8
            if should_upper != ch.isupper():
                return False
    return True


def eth_confidence(value: str) -> float:
    """0.85 shape-only, 1.0 when EIP-55 checksum verifies (keccak present)."""
    if not is_valid_eth(value):
        return 0.0
    try:
        if is_valid_eth_eip55(value) and _KECCAK_AVAILABLE:
            body = value.strip()[2:]
            if body != body.lower() and body != body.upper():
                return 1.0
    except Exception:
        pass
    return 0.85


# ---------------------------------------------------------------------------
# Extended validators: tax IDs, health IDs, geo, BIC, MRZ
# ---------------------------------------------------------------------------

def is_valid_vkn(value: str) -> bool:
    """Validate a Turkish Tax ID (VKN, 10 digits).

    Algorithm (GIB): for each of the first 9 digits
    ``tmp = (d + 10 - pos) % 10`` then ``tmp = (tmp * 2^(10-pos)) % 11``
    (pos is 1-based); check digit is ``(10 - sum % 10) % 10``.

    >>> is_valid_vkn("1234567890")
    True
    >>> is_valid_vkn("1234567891")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 10 or not digits.isdigit() or digits[0] == "0":
        return False
    if len(set(digits)) == 1:
        return False
    d = [int(c) for c in digits]
    total = 0
    for i in range(9):
        tmp = (d[i] + 10 - (i + 1)) % 10
        total += (tmp * pow(2, 10 - (i + 1), 11)) % 11
    return (10 - (total % 10)) % 10 == d[9]


def _mod11_10_check(digits: str) -> bool:
    """Shared ISO 7064 MOD 11,10 check for trailing-check-digit IDs."""
    p = 10
    for ch in digits[:-1]:
        s = (int(ch) + p) % 10
        if s == 0:
            s = 10
        p = (2 * s) % 11
    check = 0 if p == 1 else 11 - p
    return check == int(digits[-1])


def is_valid_de_tax_id(value: str) -> bool:
    """Validate a German Steuernummer (10-13 digits, MOD 11,10 key).

    Only the separated print forms (``12/345/67890``) are accepted —
    plain 11-digit runs belong to :func:`is_valid_de_idnr`.

    >>> is_valid_de_tax_id("12/345/67805")
    True
    >>> is_valid_de_tax_id("12/345/67806")
    False
    """
    if not re.search(r"[/.\- ]", value):
        return False
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 13 or digits[0] == "0":
        return False
    return _mod11_10_check(digits)


_PAN_HOLDER_CLASSES = frozenset("CPHFATBLJG")


def is_valid_pan(value: str) -> bool:
    """Validate an Indian PAN (5 letters + 4 digits + letter).

    The 4th letter encodes the holder class (C/P/H/F/A/T/B/L/J/G).

    >>> is_valid_pan("ABCPE1234F")
    True
    >>> is_valid_pan("ABCPE1234X")
    True
    >>> is_valid_pan("ABCXE1234F")
    False
    >>> is_valid_pan("ABCDE123F")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", v):
        return False
    return v[3] in _PAN_HOLDER_CLASSES


_TFN_WEIGHTS_9 = (1, 4, 3, 7, 5, 8, 6, 9, 10)


def is_valid_tfn(value: str) -> bool:
    """Validate an Australian TFN (9 digits, weighted Mod 11).

    ``sum(d[i] * w[i]) % 11 == 0`` with weights 1,4,3,7,5,8,6,9,10.
    Accepts the ``xxx xxx xxx`` print form.

    >>> is_valid_tfn("123 456 782")
    True
    >>> is_valid_tfn("123456783")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    return sum(int(c) * w for c, w in zip(digits, _TFN_WEIGHTS_9, strict=False)) % 11 == 0


def is_valid_sin(value: str) -> bool:
    """Validate a Canadian SIN (9 digits from 1-7, Luhn).

    >>> is_valid_sin("193 456 787")
    True
    >>> is_valid_sin("193-456-788")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9 or not digits.isdigit() or digits[0] not in "1234567":
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_V_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_V_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 7, 2, 5),
    (9, 4, 5, 7, 2, 6, 8, 1, 3, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _verhoeff_check(digits: str) -> bool:
    """Verhoeff checksum over a digit string (Aadhaar)."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _V_D[c][_V_P[i % 8][int(ch)]]
    return c == 0


def is_valid_aadhaar(value: str) -> bool:
    """Validate an Indian Aadhaar number (12 digits, Verhoeff).

    First digit is 2-9; accepts the ``xxxx xxxx xxxx`` print form.

    >>> is_valid_aadhaar("2345 6789 0124")
    True
    >>> is_valid_aadhaar("234567890125")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12 or not digits.isdigit() or digits[0] in "01":
        return False
    if len(set(digits)) == 1:
        return False
    _m = _native()
    if _m is not None:
        try:
            return bool(_m.verhoeff_valid(digits))
        except Exception:
            pass
    return _verhoeff_check(digits)


def is_valid_npi(value: str) -> bool:
    """Validate a US National Provider Identifier (10 digits, Luhn+80840).

    NPI starts with 1 or 2; the check is Luhn over ``80840`` + first 9.

    >>> is_valid_npi("1043477615")
    True
    >>> is_valid_npi("1043477616")
    False
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) != 10 or not digits.isdigit() or digits[0] not in "12":
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed("80840" + digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def is_valid_coordinates(value: str) -> bool:
    """Validate a GPS lat/lon pair (decimal, in range).

    >>> is_valid_coordinates("40.7128, -74.0060")
    True
    >>> is_valid_coordinates("91.0, 0.0")
    False
    """
    m = re.fullmatch(
        r"\s*([+-]?(?:[1-8]?\d\.\d+|90\.0+))\s*[,;]\s*"
        r"([+-]?(?:(?:1[0-7]\d|[1-9]?\d)\.\d+|180\.0+))\s*",
        value,
    )
    if not m:
        return False
    return abs(float(m.group(1))) <= 90 and abs(float(m.group(2))) <= 180


_ISO_ALPHA2 = frozenset(
    ["AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW", "XK"]
)


def is_valid_bic(value: str) -> bool:
    """Validate a SWIFT/BIC code (8/11 chars, ISO country at 5-6).

    >>> is_valid_bic("DEUTDEFF500")
    True
    >>> is_valid_bic("DEUTXXFF")
    False
    """
    v = value.strip().upper()
    if not re.fullmatch(r"[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?", v):
        return False
    if len(v) not in (8, 11):
        return False
    return v[4:6] in _ISO_ALPHA2


_MRZ_WEIGHTS = (7, 3, 1)


def _mrz_check(s: str) -> int:
    """ICAO Doc 9303 check digit over a field (7/3/1 weights)."""
    total = 0
    for i, ch in enumerate(s):
        if ch.isdigit():
            v = int(ch)
        elif ch.isalpha():
            v = ord(ch) - 55  # A=10 … Z=35
        else:
            v = 0  # filler '<'
        total += v * _MRZ_WEIGHTS[i % 3]
    return total % 10


def _valid_mrz_line2(line: str) -> bool:
    """Validate a TD3 second line (4 field checks + composite)."""
    if len(line) != 44:
        return False
    if not re.fullmatch(r"[A-Z0-9<]{44}", line):
        return False
    if line[9] != str(_mrz_check(line[0:9])):
        return False
    if line[19] != str(_mrz_check(line[13:19])):
        return False
    if line[27] != str(_mrz_check(line[21:27])):
        return False
    if line[42] != str(_mrz_check(line[28:42])):
        return False
    return line[43] == str(_mrz_check(line[0:10] + line[13:20] + line[21:43]))


def _is_plausible_jwt(token: str) -> bool:
    """Best-effort structural check: header segment must base64url-decode to JSON."""
    try:
        header_b64 = token.split(".")[0]
        padding = "=" * (-len(header_b64) % 4)
        decoded = base64.urlsafe_b64decode(header_b64 + padding).decode("utf-8")
        payload = json.loads(decoded)
        return isinstance(payload, dict) and ("alg" in payload or "typ" in payload)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class PIIDetector:
    """Stateless PII detector. Safe to share across streaming chunks/threads.

    Parameters
    ----------
    regions: Region filter — ``"ALL"`` (default), a single region such as
        ``"PL"``, or a combination like ``"TR,EU"`` / ``{"US", "ES"}``.
        Non-selected regions' detectors are skipped; ``GLOBAL`` detectors
        (emails, cards, IPs, JWTs, API keys) always run.
    """

    def __init__(self, regions: str | Collection[str] = "ALL",
                 custom_rules: Collection[dict] | None = None,
                 rules_dir: str | None = None) -> None:
        self.regions: frozenset[str] = normalize_regions(regions)
        if "ALL" in self.regions:
            self.enabled_types: frozenset[str] = frozenset(REGION_OF_TYPE)
        else:
            self.enabled_types = frozenset(
                t for t, r in REGION_OF_TYPE.items()
                if r in self.regions or r == "GLOBAL"
            )
        # Custom YAML/JSON rules (Faz-1 MVP): compiled lazily, never break scan.
        self._custom_specs: list[PatternSpec] = []
        self._custom_regions: dict[str, str] = {}
        self._custom_compliance: dict[str, list[str]] = {}
        _raw_rules: list[dict] = list(custom_rules or [])
        if rules_dir:
            try:
                from nukepii.core.rules import load_rules_dir as _load_dir

                _loaded, _errs = _load_dir(rules_dir)
                _raw_rules.extend([r.to_spec_kwargs() for r in _loaded])
            except Exception:
                pass
        for _r in _raw_rules:
            try:
                _rid = str(_r.get("id", "")).strip().upper()
                _pat = str(_r.get("pattern", ""))
                if not _rid or not _pat:
                    continue
                _rx = re.compile(_pat)
                _conf = float(_r.get("confidence", 0.9))
                _prio = int(_r.get("priority", 70))
                _reg = str(_r.get("region", "GLOBAL")).strip().upper() or "GLOBAL"
                _comp = _r.get("compliance", []) or []
                if isinstance(_comp, str):
                    _comp = [_comp]
                _comp = [str(c).upper() for c in _comp]
                self._custom_specs.append(PatternSpec(
                    _rid, _rx, max(0.01, min(1.0, _conf)), _prio,
                    str(_r.get("description", f"custom rule {_rid}"))))
                self._custom_regions[_rid] = _reg
                self._custom_compliance[_rid] = _comp
                if _comp:
                    _CUSTOM_COMPLIANCE[_rid] = list(_comp)
            except Exception:
                continue
        self._regex_specs: list[PatternSpec] = [
            PatternSpec("AWS_API_KEY", _AWS_KEY_RE, 1.0, 90,
                        "AWS Access Key ID"),
            PatternSpec("JWT", _JWT_RE, 0.95, 80,
                        "JSON Web Token"),
            PatternSpec("EMAIL", _EMAIL_RE, 0.95, 50,
                        "Email address"),
            PatternSpec("IPV4", _IPV4_RE, 0.90, 30,
                        "IPv4 address"),
            PatternSpec("IPV6", _IPV6_RE, 0.90, 30,
                        "IPv6 address"),
            PatternSpec("TR_PHONE", _TR_PHONE_RE, 0.90, 60,
                        "Turkish phone number"),
            PatternSpec("US_PHONE", _US_PHONE_RE, 0.90, 55,
                        "US NANP phone number"),
            PatternSpec("INTL_PHONE", _INTL_PHONE_RE, 0.85, 54,
                        "International phone number"),
            PatternSpec("GITHUB_TOKEN", _GITHUB_TOKEN_RE, 1.0, 93,
                        "GitHub token"),
            PatternSpec("SLACK_WEBHOOK", _SLACK_TOKEN_RE, 1.0, 93,
                        "Slack webhook / token"),
            PatternSpec("STRIPE_KEY", _STRIPE_KEY_RE, 1.0, 93,
                        "Stripe API key"),
            PatternSpec("OPENAI_KEY", _OPENAI_KEY_RE, 1.0, 93,
                        "OpenAI API key"),
            PatternSpec("GOOGLE_API_KEY", _GOOGLE_API_KEY_RE, 1.0, 93,
                        "Google API key"),
            PatternSpec("AZURE_KEY", _AZURE_KEY_RE, 1.0, 93,
                        "Azure account key"),
            PatternSpec("DATABASE_URL", _DATABASE_URL_RE, 0.95, 92,
                        "Database connection string"),
            PatternSpec("PRIVATE_KEY", _PRIVATE_KEY_RE, 1.0, 96,
                        "PEM private key header"),
            PatternSpec("MAC_ADDRESS", _MAC_CANDIDATE_RE, 0.95, 60,
                        "MAC-48 address"),
            PatternSpec("TELEGRAM_TOKEN", _TELEGRAM_TOKEN_RE, 1.0, 93,
                        "Telegram bot token"),
            PatternSpec("ANTHROPIC_KEY", _ANTHROPIC_KEY_RE, 1.0, 94,
                        "Anthropic API key"),
            PatternSpec("HF_TOKEN", _HF_TOKEN_RE, 1.0, 93,
                        "Hugging Face token"),
            PatternSpec("GITLAB_TOKEN", _GITLAB_TOKEN_RE, 1.0, 93,
                        "GitLab personal token"),
            PatternSpec("NPM_TOKEN", _NPM_TOKEN_RE, 1.0, 93,
                        "npm access token"),
            PatternSpec("PYPI_TOKEN", _PYPI_TOKEN_RE, 1.0, 93,
                        "PyPI API token"),
            PatternSpec("TWILIO_KEY", _TWILIO_KEY_RE, 1.0, 93,
                        "Twilio SID / API key"),
            PatternSpec("SENDGRID_KEY", _SENDGRID_KEY_RE, 1.0, 93,
                        "SendGrid API key"),
            PatternSpec("DISCORD_WEBHOOK", _DISCORD_WEBHOOK_RE, 1.0, 93,
                        "Discord webhook URL"),
            PatternSpec("IN_IFSC", _IFSC_RE, 0.95, 90,
                        "Indian IFSC bank code"),
        ]

    # -- public API ------------------------------------------------------

    def scan(self, text: str) -> list[Detection]:
        """Scan ``text`` and return deduplicated, overlap-resolved detections."""
        if not text:
            return []
        found: list[Detection] = []
        found.extend(self._scan_regex_layer(text))
        found.extend(self._scan_tr_national_ids(text))
        found.extend(self._scan_credit_cards(text))
        found.extend(self._scan_generic_api_keys(text))
        found.extend(self._scan_pesel(text))
        found.extend(self._scan_ssn(text))
        found.extend(self._scan_es_ids(text))
        found.extend(self._scan_gb_nino(text))
        found.extend(self._scan_fr_nir(text))
        found.extend(self._scan_it_fiscal(text))
        found.extend(self._scan_br_cpf(text))
        found.extend(self._scan_de_idnr(text))
        found.extend(self._scan_bsn(text))
        found.extend(self._scan_be_national(text))
        found.extend(self._scan_hetu(text))
        found.extend(self._scan_se_pnr(text))
        found.extend(self._scan_no_fnr(text))
        found.extend(self._scan_pt_nif(text))
        found.extend(self._scan_ro_cnp(text))
        found.extend(self._scan_gr_afm(text))
        found.extend(self._scan_aba(text))
        found.extend(self._scan_itin(text))
        found.extend(self._scan_isin(text))
        found.extend(self._scan_sedol(text))
        found.extend(self._scan_abn(text))
        found.extend(self._scan_cn_id(text))
        found.extend(self._scan_kr_rrn(text))
        found.extend(self._scan_sg_nric(text))
        found.extend(self._scan_il_id(text))
        found.extend(self._scan_za_id(text))
        found.extend(self._scan_th_id(text))
        found.extend(self._scan_tw_id(text))
        found.extend(self._scan_hk_id(text))
        found.extend(self._scan_jp_number(text))
        found.extend(self._scan_imei(text))
        found.extend(self._scan_vin(text))
        found.extend(self._scan_dea(text))
        found.extend(self._scan_mbi(text))
        found.extend(self._scan_btc(text))
        found.extend(self._scan_eth(text))
        found.extend(self._scan_vkn(text))
        found.extend(self._scan_de_tax(text))
        found.extend(self._scan_pan(text))
        found.extend(self._scan_tfn(text))
        found.extend(self._scan_sin(text))
        found.extend(self._scan_aadhaar(text))
        found.extend(self._scan_npi(text))
        found.extend(self._scan_coordinates(text))
        found.extend(self._scan_swift(text))
        found.extend(self._scan_passport(text))
        found.extend(self._scan_dl(text))
        found.extend(self._scan_health_id(text))
        found.extend(self._scan_iban(text))
        found.extend(self._scan_custom(text))
        return _resolve_overlaps(found)

    def _scan_custom(self, text: str) -> list[Detection]:
        """Custom YAML/JSON rules (regex-only MVP). Region-filtered."""
        out: list[Detection] = []
        if not self._custom_specs:
            return out
        for spec in self._custom_specs:
            region = self._custom_regions.get(spec.pii_type, "GLOBAL")
            if "ALL" not in self.regions and region != "GLOBAL" and region not in self.regions:
                continue
            try:
                for m in spec.pattern.finditer(text):
                    out.append({
                        "type": spec.pii_type,
                        "value": m.group(0),
                        "start": m.start(),
                        "end": m.end(),
                        "confidence": spec.confidence,
                    })
            except Exception:
                continue
        return out

    # -- layer 1: direct regex -------------------------------------------

    def _scan_regex_layer(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        for spec in self._regex_specs:
            if spec.pii_type not in self.enabled_types:
                continue
            if spec.pii_type == "EMAIL" and "@" not in text:
                continue
            for m in spec.pattern.finditer(text):
                value = m.group(0)
                if spec.pii_type == "JWT" and not _is_plausible_jwt(value):
                    continue
                if spec.pii_type == "TR_PHONE":
                    # Reject matches that are pure digit-runs of wrong length
                    # (the pattern tolerates separators, so count digits).
                    digit_count = len(re.sub(r"\D", "", value))
                    if digit_count not in (10, 11, 12, 13):
                        continue
                    # Reject a phone-shaped window inside a longer *contiguous*
                    # digit run (order IDs, timestamps, card fragments): a
                    # real TR number holds at most 14 digits (0090 + 10).
                    left = m.start()
                    while left > 0 and text[left - 1].isdigit():
                        left -= 1
                    right = m.end()
                    while right < len(text) and text[right].isdigit():
                        right += 1
                    run_digits = (m.start() - left) + digit_count + (right - m.end())
                    if run_digits > 14:
                        continue
                if spec.pii_type == "US_PHONE":
                    digits = re.sub(r"\D", "", value)
                    # NANP numbers hold 10 digits, 11 with a leading 1.
                    if len(digits) == 11:
                        if not digits.startswith("1"):
                            continue
                        digits = digits[1:]
                    if len(digits) != 10:
                        continue
                    # N11 service codes (211, 311, …) are never area codes.
                    if digits[1:3] == "11":
                        continue
                if spec.pii_type == "INTL_PHONE":
                    # E.164 caps at 15 digits; fewer than 7 is a fragment.
                    digit_count = len(re.sub(r"\D", "", value))
                    if not 7 <= digit_count <= 15:
                        continue
                out.append({
                    "type": spec.pii_type,
                    "value": value,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": spec.confidence,
                })
        return out

    # -- layer 2: algorithmic --------------------------------------------

    def _scan_tr_national_ids(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "TR_NATIONAL_ID" not in self.enabled_types:
            return out
        for m in _TR_ID_CANDIDATE_RE.finditer(text):
            value = m.group("trid")
            if is_valid_tr_national_id(value):
                out.append({
                    "type": "TR_NATIONAL_ID",
                    "value": value,
                    "start": m.start("trid"),
                    "end": m.end("trid"),
                    "confidence": 1.0,
                })
        return out

    def _scan_credit_cards(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "CREDIT_CARD" not in self.enabled_types:
            return out
        for m in _CC_CANDIDATE_RE.finditer(text):
            raw = m.group("cc")
            left_pad = len(raw) - len(raw.lstrip())
            value = raw.strip()
            # Skip anything that overlaps an already-stronger identifier shape
            # handled elsewhere (e.g. an 11-digit TR ID must not be re-tested
            # as a 13+ digit card — the regex length guard mostly covers this).
            if is_valid_luhn(value):
                start = m.start("cc") + left_pad
                out.append({
                    "type": "CREDIT_CARD",
                    "value": value,
                    "start": start,
                    "end": start + len(value),
                    "confidence": 1.0,
                })
        return out

    # -- layer 3: international IDs -----------------------------------------

    def _scan_pesel(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "PL_PESEL" not in self.enabled_types:
            return out
        for m in _PESEL_CANDIDATE_RE.finditer(text):
            value = m.group("pesel")
            if is_valid_pesel(value):
                out.append({
                    "type": "PL_PESEL",
                    "value": value,
                    "start": m.start("pesel"),
                    "end": m.end("pesel"),
                    "confidence": 1.0,
                })
        return out

    def _scan_ssn(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "US_SSN" not in self.enabled_types:
            return out
        for m in _SSN_CANDIDATE_RE.finditer(text):
            value = m.group("ssn")
            if is_valid_ssn(value):
                out.append({
                    "type": "US_SSN",
                    "value": value,
                    "start": m.start("ssn"),
                    "end": m.end("ssn"),
                    "confidence": 0.95,
                })
        return out

    def _scan_es_ids(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        want_nif = "ES_NIF" in self.enabled_types
        want_nie = "ES_NIE" in self.enabled_types
        if not (want_nif or want_nie):
            return out
        for m in _NIF_CANDIDATE_RE.finditer(text):
            if not want_nif:
                break
            value = m.group("nif")
            if is_valid_nif(value):
                out.append({
                    "type": "ES_NIF",
                    "value": value,
                    "start": m.start("nif"),
                    "end": m.end("nif"),
                    "confidence": 1.0,
                })
        for m in _NIE_CANDIDATE_RE.finditer(text):
            if not want_nie:
                break
            value = m.group("nie")
            if is_valid_nie(value):
                out.append({
                    "type": "ES_NIE",
                    "value": value,
                    "start": m.start("nie"),
                    "end": m.end("nie"),
                    "confidence": 1.0,
                })
        return out

    def _scan_gb_nino(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "GB_NINO" not in self.enabled_types:
            return out
        for m in _NINO_CANDIDATE_RE.finditer(text):
            value = m.group("nino")
            if is_valid_nino(value):
                out.append({
                    "type": "GB_NINO",
                    "value": value,
                    "start": m.start("nino"),
                    "end": m.end("nino"),
                    "confidence": 1.0,
                })
        return out

    def _scan_fr_nir(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "FR_NIR" not in self.enabled_types:
            return out
        for m in _NIR_CANDIDATE_RE.finditer(text):
            value = m.group("nir").strip()
            if is_valid_nir(value):
                start = m.start("nir")
                out.append({
                    "type": "FR_NIR",
                    "value": value,
                    "start": start,
                    "end": start + len(value),
                    "confidence": 1.0,
                })
        return out

    def _scan_it_fiscal(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "IT_FISCAL" not in self.enabled_types:
            return out
        for m in _FISCAL_CANDIDATE_RE.finditer(text):
            value = m.group("fisc")
            if is_valid_fiscal(value):
                out.append({
                    "type": "IT_FISCAL",
                    "value": value,
                    "start": m.start("fisc"),
                    "end": m.end("fisc"),
                    "confidence": 1.0,
                })
        return out

    def _scan_br_cpf(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "BR_CPF" not in self.enabled_types:
            return out
        for m in _CPF_CANDIDATE_RE.finditer(text):
            value = m.group("cpf")
            if is_valid_cpf(value):
                out.append({
                    "type": "BR_CPF",
                    "value": value,
                    "start": m.start("cpf"),
                    "end": m.end("cpf"),
                    "confidence": 1.0,
                })
        return out

    def _scan_de_idnr(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "DE_IDNR" not in self.enabled_types:
            return out
        for m in _DEIDNR_CANDIDATE_RE.finditer(text):
            value = m.group("deid")
            if is_valid_de_idnr(value):
                out.append({
                    "type": "DE_IDNR",
                    "value": value,
                    "start": m.start("deid"),
                    "end": m.end("deid"),
                    "confidence": 1.0,
                })
        return out

    # -- layer 4: EU national IDs ------------------------------------------

    def _scan_bsn(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "NL_BSN" not in self.enabled_types:
            return out
        for m in _BSN_CANDIDATE_RE.finditer(text):
            value = m.group("bsn")
            if is_valid_bsn(value):
                out.append({
                    "type": "NL_BSN",
                    "value": value,
                    "start": m.start("bsn"),
                    "end": m.end("bsn"),
                    "confidence": 1.0,
                })
        return out

    def _scan_be_national(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "BE_NATIONAL_ID" not in self.enabled_types:
            return out
        for m in _BE_CANDIDATE_RE.finditer(text):
            value = m.group("be")
            if is_valid_be_national(value):
                out.append({
                    "type": "BE_NATIONAL_ID",
                    "value": value,
                    "start": m.start("be"),
                    "end": m.end("be"),
                    "confidence": 1.0,
                })
        return out

    def _scan_hetu(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "FI_HETU" not in self.enabled_types:
            return out
        for m in _HETU_CANDIDATE_RE.finditer(text):
            value = m.group("hetu")
            if is_valid_hetu(value):
                out.append({
                    "type": "FI_HETU",
                    "value": value,
                    "start": m.start("hetu"),
                    "end": m.end("hetu"),
                    "confidence": 1.0,
                })
        return out

    def _scan_se_pnr(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "SE_PERSONNUMMER" not in self.enabled_types:
            return out
        for m in _SE_CANDIDATE_RE.finditer(text):
            value = m.group("se")
            if is_valid_se_pnr(value):
                out.append({
                    "type": "SE_PERSONNUMMER",
                    "value": value,
                    "start": m.start("se"),
                    "end": m.end("se"),
                    "confidence": 1.0,
                })
        return out

    def _scan_no_fnr(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "NO_FODSELSNUMMER" not in self.enabled_types:
            return out
        for m in _NO_CANDIDATE_RE.finditer(text):
            value = m.group("no")
            if is_valid_no_fnr(value):
                out.append({
                    "type": "NO_FODSELSNUMMER",
                    "value": value,
                    "start": m.start("no"),
                    "end": m.end("no"),
                    "confidence": 1.0,
                })
        return out

    def _scan_pt_nif(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "PT_NIF" not in self.enabled_types:
            return out
        for m in _PT_CANDIDATE_RE.finditer(text):
            value = m.group("pt")
            if is_valid_pt_nif(value):
                out.append({
                    "type": "PT_NIF",
                    "value": value,
                    "start": m.start("pt"),
                    "end": m.end("pt"),
                    "confidence": 1.0,
                })
        return out

    def _scan_ro_cnp(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "RO_CNP" not in self.enabled_types:
            return out
        for m in _RO_CANDIDATE_RE.finditer(text):
            value = m.group("ro")
            if is_valid_ro_cnp(value):
                out.append({
                    "type": "RO_CNP",
                    "value": value,
                    "start": m.start("ro"),
                    "end": m.end("ro"),
                    "confidence": 1.0,
                })
        return out

    def _scan_gr_afm(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "GR_AFM" not in self.enabled_types:
            return out
        for m in _GR_CANDIDATE_RE.finditer(text):
            value = m.group("gr")
            if is_valid_gr_afm(value):
                out.append({
                    "type": "GR_AFM",
                    "value": value,
                    "start": m.start("gr"),
                    "end": m.end("gr"),
                    "confidence": 1.0,
                })
        return out

    def _scan_gr_afm(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "GR_AFM" not in self.enabled_types:
            return out
        for m in _GR_CANDIDATE_RE.finditer(text):
            value = m.group("gr")
            if is_valid_gr_afm(value):
                out.append({
                    "type": "GR_AFM",
                    "value": value,
                    "start": m.start("gr"),
                    "end": m.end("gr"),
                    "confidence": 1.0,
                })
        return out

    # -- layer 5: financial identifiers -------------------------------------

    def _scan_aba(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "US_ABA" not in self.enabled_types:
            return out
        for m in _ABA_CANDIDATE_RE.finditer(text):
            value = m.group("aba")
            if is_valid_aba(value):
                out.append({
                    "type": "US_ABA",
                    "value": value,
                    "start": m.start("aba"),
                    "end": m.end("aba"),
                    "confidence": 1.0,
                })
        return out

    def _scan_itin(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "US_ITIN" not in self.enabled_types:
            return out
        for m in _ITIN_CANDIDATE_RE.finditer(text):
            value = m.group("itin")
            if is_valid_itin(value):
                out.append({
                    "type": "US_ITIN",
                    "value": value,
                    "start": m.start("itin"),
                    "end": m.end("itin"),
                    "confidence": 0.95,
                })
        return out

    def _scan_isin(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "ISIN" not in self.enabled_types:
            return out
        for m in _ISIN_CANDIDATE_RE.finditer(text):
            value = m.group("isin")
            if is_valid_isin(value):
                out.append({
                    "type": "ISIN",
                    "value": value,
                    "start": m.start("isin"),
                    "end": m.end("isin"),
                    "confidence": 1.0,
                })
        return out

    def _scan_sedol(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "SEDOL" not in self.enabled_types:
            return out
        for m in _SEDOL_CANDIDATE_RE.finditer(text):
            value = m.group("sedol")
            if is_valid_sedol(value):
                out.append({
                    "type": "SEDOL",
                    "value": value.upper(),
                    "start": m.start("sedol"),
                    "end": m.end("sedol"),
                    "confidence": 0.95,
                })
        return out

    def _scan_abn(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "AU_ABN" not in self.enabled_types:
            return out
        for m in _ABN_CANDIDATE_RE.finditer(text):
            value = m.group("abn")
            if is_valid_abn(value):
                out.append({
                    "type": "AU_ABN",
                    "value": value,
                    "start": m.start("abn"),
                    "end": m.end("abn"),
                    "confidence": 1.0,
                })
        return out

    # -- layer 6: APAC/MEA IDs + devices -----------------------------------

    def _scan_cn_id(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "CN_ID" not in self.enabled_types:
            return out
        for m in _CN_CANDIDATE_RE.finditer(text):
            value = m.group("cn")
            if is_valid_cn_id(value):
                out.append({
                    "type": "CN_ID",
                    "value": value.upper(),
                    "start": m.start("cn"),
                    "end": m.end("cn"),
                    "confidence": 1.0,
                })
        return out

    def _scan_kr_rrn(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "KR_RRN" not in self.enabled_types:
            return out
        for m in _KR_CANDIDATE_RE.finditer(text):
            value = m.group("kr")
            if is_valid_kr_rrn(value):
                out.append({
                    "type": "KR_RRN",
                    "value": value,
                    "start": m.start("kr"),
                    "end": m.end("kr"),
                    "confidence": 1.0,
                })
        return out

    def _scan_sg_nric(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "SG_NRIC" not in self.enabled_types:
            return out
        for m in _SG_CANDIDATE_RE.finditer(text):
            value = m.group("sg")
            if is_valid_sg_nric(value):
                out.append({
                    "type": "SG_NRIC",
                    "value": value.upper(),
                    "start": m.start("sg"),
                    "end": m.end("sg"),
                    "confidence": 1.0,
                })
        return out

    def _scan_il_id(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "IL_ID" not in self.enabled_types:
            return out
        for m in _IL_CANDIDATE_RE.finditer(text):
            value = m.group("il")
            if is_valid_il_id(value):
                out.append({
                    "type": "IL_ID",
                    "value": value,
                    "start": m.start("il"),
                    "end": m.end("il"),
                    "confidence": 1.0,
                })
        return out

    def _scan_za_id(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "ZA_ID" not in self.enabled_types:
            return out
        for m in _ZA_CANDIDATE_RE.finditer(text):
            value = m.group("za")
            if is_valid_za_id(value):
                out.append({
                    "type": "ZA_ID",
                    "value": value,
                    "start": m.start("za"),
                    "end": m.end("za"),
                    "confidence": 1.0,
                })
        return out

    def _scan_th_id(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "TH_ID" not in self.enabled_types:
            return out
        for m in _TH_CANDIDATE_RE.finditer(text):
            value = m.group("th")
            if is_valid_th_id(value):
                out.append({
                    "type": "TH_ID",
                    "value": value,
                    "start": m.start("th"),
                    "end": m.end("th"),
                    "confidence": 1.0,
                })
        return out

    def _scan_tw_id(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "TW_ID" not in self.enabled_types:
            return out
        for m in _TW_CANDIDATE_RE.finditer(text):
            value = m.group("tw")
            if is_valid_tw_id(value):
                out.append({
                    "type": "TW_ID",
                    "value": value.upper(),
                    "start": m.start("tw"),
                    "end": m.end("tw"),
                    "confidence": 1.0,
                })
        return out

    def _scan_hk_id(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "HK_ID" not in self.enabled_types:
            return out
        for m in _HK_CANDIDATE_RE.finditer(text):
            value = m.group("hk")
            if is_valid_hk_id(value):
                out.append({
                    "type": "HK_ID",
                    "value": value.upper(),
                    "start": m.start("hk"),
                    "end": m.end("hk"),
                    "confidence": 0.95,
                })
        return out

    def _scan_jp_number(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "JP_MY_NUMBER" not in self.enabled_types:
            return out
        for m in _JP_CANDIDATE_RE.finditer(text):
            value = m.group("jp")
            if is_valid_jp_number(value):
                out.append({
                    "type": "JP_MY_NUMBER",
                    "value": value,
                    "start": m.start("jp"),
                    "end": m.end("jp"),
                    "confidence": 1.0,
                })
        return out

    def _scan_imei(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "IMEI" not in self.enabled_types:
            return out
        for m in _IMEI_CONTEXT_RE.finditer(text):
            value = m.group("imei").strip().rstrip("\"'")
            if not re.fullmatch(r"\d{15}", value):
                continue
            if is_valid_imei(value):
                start = m.start("imei")
                out.append({
                    "type": "IMEI",
                    "value": value,
                    "start": start,
                    "end": start + len(value),
                    "confidence": 1.0,
                })
        return out

    def _scan_vin(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "VIN" not in self.enabled_types:
            return out
        for m in _VIN_CANDIDATE_RE.finditer(text):
            value = m.group("vin")
            if is_valid_vin(value):
                out.append({
                    "type": "VIN",
                    "value": value.upper(),
                    "start": m.start("vin"),
                    "end": m.end("vin"),
                    "confidence": 1.0,
                })
        return out

    # -- layer 7: health + crypto ------------------------------------------

    def _scan_dea(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "US_DEA" not in self.enabled_types:
            return out
        for m in _DEA_CANDIDATE_RE.finditer(text):
            value = m.group("dea")
            if is_valid_dea(value):
                out.append({
                    "type": "US_DEA",
                    "value": value.upper(),
                    "start": m.start("dea"),
                    "end": m.end("dea"),
                    "confidence": 1.0,
                })
        return out

    def _scan_mbi(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "US_MBI" not in self.enabled_types:
            return out
        for m in _MBI_CANDIDATE_RE.finditer(text):
            value = m.group("mbi")
            if is_valid_mbi(value):
                out.append({
                    "type": "US_MBI",
                    "value": value.upper(),
                    "start": m.start("mbi"),
                    "end": m.end("mbi"),
                    "confidence": 0.95,
                })
        return out

    def _scan_btc(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "BTC_ADDRESS" not in self.enabled_types:
            return out
        for m in _BTC_CANDIDATE_RE.finditer(text):
            value = m.group("btc")
            if is_valid_btc(value):
                out.append({
                    "type": "BTC_ADDRESS",
                    "value": value,
                    "start": m.start("btc"),
                    "end": m.end("btc"),
                    "confidence": 1.0,
                })
        return out

    def _scan_eth(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "ETH_ADDRESS" not in self.enabled_types:
            return out
        for m in _ETH_CANDIDATE_RE.finditer(text):
            value = m.group("eth")
            conf = eth_confidence(value)
            if conf > 0:
                out.append({
                    "type": "ETH_ADDRESS",
                    "value": value,
                    "start": m.start("eth"),
                    "end": m.end("eth"),
                    "confidence": conf,
                })
        return out

    def _scan_vkn(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "TR_VKN" not in self.enabled_types:
            return out
        for m in _VKN_CANDIDATE_RE.finditer(text):
            value = m.group("vkn")
            if is_valid_vkn(value):
                out.append({
                    "type": "TR_VKN",
                    "value": value,
                    "start": m.start("vkn"),
                    "end": m.end("vkn"),
                    "confidence": 1.0,
                })
        return out

    def _scan_de_tax(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "DE_TAX_ID" not in self.enabled_types:
            return out
        for m in _DETAX_CANDIDATE_RE.finditer(text):
            value = m.group("detax")
            if is_valid_de_tax_id(value):
                out.append({
                    "type": "DE_TAX_ID",
                    "value": value,
                    "start": m.start("detax"),
                    "end": m.end("detax"),
                    "confidence": 0.95,
                })
        return out

    def _scan_pan(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "IN_PAN" not in self.enabled_types:
            return out
        for m in _PAN_CANDIDATE_RE.finditer(text):
            value = m.group("pan")
            if is_valid_pan(value):
                out.append({
                    "type": "IN_PAN",
                    "value": value,
                    "start": m.start("pan"),
                    "end": m.end("pan"),
                    "confidence": 1.0,
                })
        return out

    def _scan_tfn(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "AU_TFN" not in self.enabled_types:
            return out
        for m in _TFN_CANDIDATE_RE.finditer(text):
            value = m.group("tfn")
            if is_valid_tfn(value):
                out.append({
                    "type": "AU_TFN",
                    "value": value,
                    "start": m.start("tfn"),
                    "end": m.end("tfn"),
                    "confidence": 1.0,
                })
        return out

    def _scan_sin(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "CA_SIN" not in self.enabled_types:
            return out
        for m in _SIN_CANDIDATE_RE.finditer(text):
            value = m.group("sin")
            if is_valid_sin(value):
                out.append({
                    "type": "CA_SIN",
                    "value": value,
                    "start": m.start("sin"),
                    "end": m.end("sin"),
                    "confidence": 1.0,
                })
        return out

    def _scan_aadhaar(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "IN_AADHAAR" not in self.enabled_types:
            return out
        for m in _AADHAAR_CANDIDATE_RE.finditer(text):
            value = m.group("aad")
            if is_valid_aadhaar(value):
                out.append({
                    "type": "IN_AADHAAR",
                    "value": value,
                    "start": m.start("aad"),
                    "end": m.end("aad"),
                    "confidence": 1.0,
                })
        return out

    def _scan_npi(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "US_NPI" not in self.enabled_types:
            return out
        for m in _NPI_CANDIDATE_RE.finditer(text):
            value = m.group("npi")
            if is_valid_npi(value):
                out.append({
                    "type": "US_NPI",
                    "value": value,
                    "start": m.start("npi"),
                    "end": m.end("npi"),
                    "confidence": 1.0,
                })
        return out

    def _scan_coordinates(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "COORDINATES" not in self.enabled_types:
            return out
        for m in _COORD_CANDIDATE_RE.finditer(text):
            value = m.group("coord")
            if is_valid_coordinates(value):
                out.append({
                    "type": "COORDINATES",
                    "value": value,
                    "start": m.start("coord"),
                    "end": m.end("coord"),
                    "confidence": 0.9,
                })
        return out

    def _scan_swift(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "SWIFT_BIC" not in self.enabled_types:
            return out
        for m in _BIC_CANDIDATE_RE.finditer(text):
            value = m.group("bic")
            if not is_valid_bic(value):
                continue
            if len(value) == 8 and not re.search(
                    r"(?i)(swift|bic|bank|rout)", text[max(0, m.start() - 24):m.end() + 24]):
                continue
            out.append({
                "type": "SWIFT_BIC",
                "value": value,
                "start": m.start("bic"),
                "end": m.end("bic"),
                "confidence": 1.0 if len(value) == 11 else 0.9,
            })
        return out

    def _scan_passport(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "PASSPORT" not in self.enabled_types:
            return out
        lines = [(m.group("mrz"), m.start("mrz"), m.end("mrz"))
                 for m in _MRZ_LINE_RE.finditer(text)]
        used: set = set()
        for i, (line, start, end) in enumerate(lines):
            if i in used:
                continue
            # TD3 pair: P-line immediately followed by a valid line 2.
            if line.startswith("P") and i + 1 < len(lines) \
                    and lines[i + 1][1] == end + 1 \
                    and _valid_mrz_line2(lines[i + 1][0]):
                out.append({
                    "type": "PASSPORT",
                    "value": text[start:lines[i + 1][2]],
                    "start": start,
                    "end": lines[i + 1][2],
                    "confidence": 1.0,
                })
                used.update((i, i + 1))
            elif not line.startswith("P") and _valid_mrz_line2(line):
                out.append({
                    "type": "PASSPORT",
                    "value": line,
                    "start": start,
                    "end": end,
                    "confidence": 1.0,
                })
                used.add(i)
        return out

    def _scan_dl(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "DRIVERS_LICENSE" not in self.enabled_types:
            return out
        pos = 0
        while True:
            m = _DL_CONTEXT_RE.search(text, pos)
            if not m:
                break
            value = _trim_trailing_words(m.group("dl").strip().rstrip("\"'"))
            if not value or _has_label_word(value, _DL_LABEL_WORDS):
                pos = m.start() + 1
                continue
            compact = re.sub(r"[\s\-]", "", value)
            if not 5 <= len(compact) <= 20:
                pos = m.end()
                continue
            if not (re.search(r"[A-Z]", compact, re.IGNORECASE)
                    and re.search(r"\d", compact)):
                pos = m.end()
                continue
            start = m.start("dl")
            out.append({
                "type": "DRIVERS_LICENSE",
                "value": value,
                "start": start,
                "end": start + len(value),
                "confidence": 0.9,
            })
            pos = m.end()
        return out

    def _scan_health_id(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "HEALTH_INSURANCE_ID" not in self.enabled_types:
            return out
        pos = 0
        while True:
            m = _HEALTH_CONTEXT_RE.search(text, pos)
            if not m:
                break
            value = _trim_trailing_words(m.group("hi").strip().rstrip("\"'"))
            if not value or _has_label_word(value, _HEALTH_LABEL_WORDS):
                pos = m.start() + 1
                continue
            compact = re.sub(r"[\s\-]", "", value)
            if not 6 <= len(compact) <= 20:
                pos = m.end()
                continue
            start = m.start("hi")
            out.append({
                "type": "HEALTH_INSURANCE_ID",
                "value": value,
                "start": start,
                "end": start + len(value),
                "confidence": 0.85,
            })
            pos = m.end()
        return out

    def _scan_iban(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "IBAN" not in self.enabled_types:
            return out
        for m in _IBAN_CANDIDATE_RE.finditer(text):
            value = m.group("iban")
            if is_valid_iban(value):
                out.append({
                    "type": "IBAN",
                    "value": value,
                    "start": m.start("iban"),
                    "end": m.end("iban"),
                    "confidence": 1.0,
                })
        return out

    def _scan_generic_api_keys(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        if "GENERIC_API_KEY" not in self.enabled_types:
            return out
        for m in _GENERIC_API_KEY_RE.finditer(text):
            secret = m.group("secret").rstrip("\"'")  # drop trailing quote if any
            if len(secret) < 16:
                continue
            # Entropy-lite guard: require a mix of chars OR long length so that
            # `password = "................"` placeholders don't all flag.
            unique_ratio = len(set(secret)) / max(len(secret), 1)
            confidence = 0.75 if (unique_ratio > 0.4 or len(secret) >= 24) else 0.60
            out.append({
                "type": "GENERIC_API_KEY",
                "value": secret,
                "start": m.start("secret"),
                "end": m.start("secret") + len(secret),
                "confidence": round(confidence, 2),
            })
        return out


# ---------------------------------------------------------------------------
# Overlap resolution + module-level convenience API
# ---------------------------------------------------------------------------

_PRIORITY: dict[str, int] = {
    "TR_NATIONAL_ID": 100,
    "TR_VKN": 100,
    "FR_NIR": 99,
    "PL_PESEL": 98,
    "IBAN": 97,
    "GB_NINO": 97,
    "IN_AADHAAR": 97,
    "ES_NIF": 96,
    "ES_NIE": 96,
    "IT_FISCAL": 96,
    "IN_PAN": 96,
    "AU_TFN": 96,
    "CA_SIN": 96,
    "US_NPI": 96,
    "PRIVATE_KEY": 96,
    "CREDIT_CARD": 95,
    "DE_TAX_ID": 95,
    "BR_CPF": 94,
    "NL_BSN": 95,
    "BE_NATIONAL_ID": 97,
    "FI_HETU": 96,
    "SE_PERSONNUMMER": 98,
    "NO_FODSELSNUMMER": 97,
    "PT_NIF": 95,
    "RO_CNP": 96,
    "GR_AFM": 95,
    "US_ABA": 90,
    "US_ITIN": 85,
    "ISIN": 90,
    "SEDOL": 90,
    "IN_IFSC": 90,
    "AU_ABN": 94,
    "CN_ID": 97,
    "KR_RRN": 97,
    "SG_NRIC": 96,
    "IL_ID": 89,
    "ZA_ID": 96,
    "TH_ID": 96,
    "TW_ID": 96,
    "HK_ID": 96,
    "JP_MY_NUMBER": 97,
    "IMEI": 96,
    "VIN": 90,
    "US_DEA": 96,
    "US_MBI": 90,
    "BTC_ADDRESS": 90,
    "ETH_ADDRESS": 85,
    "TELEGRAM_TOKEN": 93,
    "ANTHROPIC_KEY": 94,
    "HF_TOKEN": 93,
    "GITLAB_TOKEN": 93,
    "NPM_TOKEN": 93,
    "PYPI_TOKEN": 93,
    "TWILIO_KEY": 93,
    "SENDGRID_KEY": 93,
    "DISCORD_WEBHOOK": 93,
    "DE_IDNR": 93,
    "GITHUB_TOKEN": 93,
    "STRIPE_KEY": 93,
    "OPENAI_KEY": 93,
    "GOOGLE_API_KEY": 93,
    "AZURE_KEY": 93,
    "SLACK_WEBHOOK": 93,
    "DATABASE_URL": 92,
    "AWS_API_KEY": 90,
    "PASSPORT": 90,
    "SWIFT_BIC": 90,
    "US_SSN": 85,
    "JWT": 80,
    "DRIVERS_LICENSE": 70,
    "HEALTH_INSURANCE_ID": 70,
    "GENERIC_API_KEY": 70,
    "TR_PHONE": 60,
    "MAC_ADDRESS": 60,
    "COORDINATES": 60,
    "US_PHONE": 55,
    "INTL_PHONE": 54,
    "EMAIL": 50,
    "IPV4": 30,
    "IPV6": 30,
}


def _resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """Drop overlapping detections, keeping highest (confidence, priority, length)."""
    if len(detections) < 2:
        return sorted(detections, key=lambda d: d["start"])
    ranked = sorted(
        detections,
        key=lambda d: (
            -d["confidence"],
            -_PRIORITY.get(d["type"], 0),
            -(d["end"] - d["start"]),
            d["start"],
        ),
    )
    kept: list[Detection] = []
    occupied: list[tuple[int, int]] = []
    for det in ranked:
        if any(det["start"] < e and det["end"] > s for s, e in occupied):
            continue
        kept.append(det)
        occupied.append((det["start"], det["end"]))
    return sorted(kept, key=lambda d: d["start"])


_DEFAULT_DETECTOR = PIIDetector()


def scan_text(text: str, detector: PIIDetector | None = None) -> list[Detection]:
    """Convenience wrapper — scan ``text`` with the shared default detector."""
    return (detector or _DEFAULT_DETECTOR).scan(text)


def detection_to_dict(detection: Detection) -> dict[str, object]:
    """Return a JSON-serializable copy of a detection dict."""
    return dict(detection)


RISK_FACTOR = 20.0  # risk = min(100, severity_sum / units * RISK_FACTOR)


def compute_risk_score(breakdown: dict[str, int], units: int) -> tuple[int, str]:
    """Map (severity-weighted hits, units scanned) -> (0-100 score, label).

    Formula: ``score = min(100, round(severity_sum / max(units,1) * 20))``
    where ``severity_sum = sum(count[t] * SEVERITY_WEIGHTS[t])``.
    A file where every record carries a high-severity hit saturates at 100;
    a lone email in a 1000-line log scores ~0. Thresholds: <25 LOW,
    <50 MODERATE, <75 HIGH, else CRITICAL.

    Single source of truth — shared by the streamer, CLI and web dashboard.
    """
    severity_sum = sum(count * SEVERITY_WEIGHTS.get(ptype, 1.0)
                       for ptype, count in breakdown.items())
    score = min(100, round(severity_sum / max(units, 1) * RISK_FACTOR)) if breakdown else 0
    if score < 25:
        label = "LOW"
    elif score < 50:
        label = "MODERATE"
    elif score < 75:
        label = "HIGH"
    else:
        label = "CRITICAL"
    return score, label


__all__ = [
    "COMPLIANCE_OF_TYPE",
    "PII_TYPES",
    "REGIONS",
    "REGION_OF_TYPE",
    "RISK_FACTOR",
    "SEVERITY_WEIGHTS",
    "Detection",
    "PIIDetector",
    "PatternSpec",
    "compliance_for",
    "compliance_summary",
    "compute_risk_score",
    "detection_to_dict",
    "eth_confidence",
    "extract_pesel_dob",
    "is_valid_aadhaar",
    "is_valid_aba",
    "is_valid_abn",
    "is_valid_be_national",
    "is_valid_bic",
    "is_valid_bsn",
    "is_valid_btc",
    "is_valid_cn_id",
    "is_valid_coordinates",
    "is_valid_cpf",
    "is_valid_de_idnr",
    "is_valid_de_tax_id",
    "is_valid_dea",
    "is_valid_eth",
    "is_valid_eth_eip55",
    "is_valid_fiscal",
    "is_valid_gr_afm",
    "is_valid_hetu",
    "is_valid_hk_id",
    "is_valid_iban",
    "is_valid_il_id",
    "is_valid_imei",
    "is_valid_isin",
    "is_valid_itin",
    "is_valid_jp_number",
    "is_valid_kr_rrn",
    "is_valid_luhn",
    "is_valid_mbi",
    "is_valid_nie",
    "is_valid_nif",
    "is_valid_nino",
    "is_valid_nir",
    "is_valid_no_fnr",
    "is_valid_npi",
    "is_valid_pan",
    "is_valid_pesel",
    "is_valid_pt_nif",
    "is_valid_ro_cnp",
    "is_valid_se_pnr",
    "is_valid_sedol",
    "is_valid_sg_nric",
    "is_valid_sin",
    "is_valid_ssn",
    "is_valid_tfn",
    "is_valid_th_id",
    "is_valid_tr_national_id",
    "is_valid_tw_id",
    "is_valid_vin",
    "is_valid_vkn",
    "is_valid_za_id",
    "normalize_regions",
    "scan_text",
]
