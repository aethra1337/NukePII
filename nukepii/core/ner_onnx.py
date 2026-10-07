"""ONNX NER stub — Faz-3 (optional, disabled by default).

Interface is stable so Faz-3 model drop-in needs no call-site change:

    from nukepii.core.ner_onnx import available, scan_ner
    if available(): dets += scan_ner(text)  # PER/LOC/ORG, low priority

Faz-2 delivers the stub (always available()=False unless onnxruntime +
model file present). Model: quantized MiniLM token-classification,
128-token sliding window, cached under ~/.cache/nukepii/models.
"""

from __future__ import annotations

from pathlib import Path

MODEL_ENV = "NUKEPII_NER_MODEL"
CACHE_DIR = Path.home() / ".cache" / "nukepii" / "models"


def available() -> bool:
    try:
        import onnxruntime  # type: ignore  # noqa: F401
    except Exception:
        return False
    import os

    p = os.getenv(MODEL_ENV, "")
    if p and Path(p).is_file():
        return True
    return any(CACHE_DIR.glob("*.onnx"))


def scan_ner(text: str, threshold: float = 0.85) -> list[dict]:
    """Faz-3 real impl; Faz-2 returns [] (model not bundled)."""
    if not available() or not text or not text.strip():
        return []
    # Placeholder: model wiring lands in Faz-3; keep empty to avoid FP.
    return []


__all__ = ["CACHE_DIR", "MODEL_ENV", "available", "scan_ner"]
