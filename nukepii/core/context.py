"""Syntactic context guarding — Faz-1/3 lexical layer.

Scores ±window words around a candidate span to boost/suppress
context-gated detectors (IMEI, DRIVERS_LICENSE, HEALTH_INSURANCE_ID,
SWIFT 8-char, PASSPORT). O(1) dict lookup, no ML dependency.

Faz-3 will add TF-IDF/N-gram + ONNX NER on top of this API.
"""

from __future__ import annotations

import re

LEXICON: dict[str, float] = {
    "imei": 1.0, "passport": 0.9, "visa": 0.5, "mrz": 1.0,
    "driver": 0.8, "license": 0.7, "dl": 0.6, "licence": 0.7,
    "policy": 0.7, "member": 0.6, "patient": 0.7, "medicare": 0.9,
    "medicaid": 0.9, "health": 0.5, "insurance": 0.6, "subscriber": 0.7,
    "swift": 0.9, "bic": 0.9, "bank": 0.4, "routing": 0.4,
    "iban": 0.9, "account": 0.3,
}

_WORD_RE = re.compile(r"[a-z]{2,}")


def context_boost(text: str, start: int, end: int, window: int = 40) -> float:
    """Return 0.0..1.0 context score for span [start:end)."""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    words = _WORD_RE.findall(text[lo:hi].lower())
    if not words:
        return 0.0
    return max((LEXICON.get(w, 0.0) for w in words), default=0.0)


def passes_context(text: str, start: int, end: int, threshold: float = 0.4,
                   window: int = 40) -> bool:
    return context_boost(text, start, end, window) >= threshold


__all__ = ["LEXICON", "context_boost", "passes_context"]
