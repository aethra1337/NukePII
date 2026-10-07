"""OCR extractor stub — Faz-3 (optional Tesseract/EasyOCR).

scan_image(path) -> [(text, bbox)] with graceful ImportError.
Bounded memory: single image at a time, downscaled to max 2000px.
"""

from __future__ import annotations

from typing import Any


def available() -> bool:
    try:
        import PIL  # type: ignore  # noqa: F401
    except Exception:
        return False
    try:
        import pytesseract  # type: ignore  # noqa: F401

        return True
    except Exception:
        pass
    try:
        import easyocr  # type: ignore  # noqa: F401

        return True
    except Exception:
        return False


def scan_image(path: str) -> list[dict[str, Any]]:
    if not available():
        raise ImportError("OCR requires pillow + (pytesseract|easyocr)")
    try:
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore

        img = Image.open(path)
        img.thumbnail((2000, 2000))
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        out: list[dict[str, Any]] = []
        for i, txt in enumerate(data.get("text", [])):
            if txt and txt.strip():
                out.append({"text": txt, "bbox": (
                    data["left"][i], data["top"][i],
                    data["width"][i], data["height"][i])})
        return out
    except Exception as exc:
        raise RuntimeError(f"OCR failed for {path}: {exc}") from exc


__all__ = ["available", "scan_image"]
