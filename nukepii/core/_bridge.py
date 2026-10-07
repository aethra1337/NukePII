"""Native-extension bridge — Rust/PyO3 entry point.

`nukepii._native` is OPTIONAL (built via maturin from `rust/`, see
`rust/README.md`). When absent — e.g. machines without VS Build Tools or
with Smart App Control on — every caller silently uses the pure-Python
validators in `detectors.py`. Zero new processes, zero new binaries at
runtime; this module only does a guarded import.

Install a CI-built wheel and restart: `capabilities()["native"]`
flips to True and the hot-path validators below accelerate automatically.
"""

from __future__ import annotations

from typing import Any

try:
    from nukepii import _native as _mod  # type: ignore

    NATIVE_AVAILABLE = True
except Exception:
    _mod = None  # type: ignore
    NATIVE_AVAILABLE = False

NATIVE_BACKEND = "rust" if NATIVE_AVAILABLE else "python"


def mod() -> Any:
    """Return the native module or None (never raises)."""
    return _mod


def native_info() -> dict[str, Any]:
    if _mod is not None:
        try:
            return dict(_mod.native_info())
        except Exception:
            pass
    return {"crate": "nukepii-native (not built)",
            "backend": "python-fallback"}


def scan_batch(texts: list[str]) -> list[list[dict]]:
    """Placeholder for a full-Rust scanner (Faz-3+). Always falls back today."""
    raise NotImplementedError("native scanner not built yet (see rust/README.md)")


__all__ = ["NATIVE_AVAILABLE", "NATIVE_BACKEND", "mod", "native_info", "scan_batch"]
