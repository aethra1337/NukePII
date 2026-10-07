"""Multi-format extractors — Faz-2 (streaming, bounded memory).

Extractor protocol: iter_units(path) -> (unit_id, text, meta).
Supported when optional deps present, else raise ImportError with hint.

  parquet / avro / xlsx / docx / pdf-text
Image OCR lives in `extractors_ocr.py` (optional Tesseract/EasyOCR).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, TypedDict


class ExtractedUnit(TypedDict):
    id: str
    text: str
    meta: dict[str, Any]


def available_formats() -> dict[str, bool]:
    out: dict[str, bool] = {}
    try:
        import pyarrow.parquet  # type: ignore  # noqa: F401

        out["parquet"] = True
    except Exception:
        out["parquet"] = False
    try:
        import fastavro  # type: ignore  # noqa: F401

        out["avro"] = True
    except Exception:
        out["avro"] = False
    try:
        import openpyxl  # type: ignore  # noqa: F401

        out["xlsx"] = True
    except Exception:
        out["xlsx"] = False
    try:
        import docx  # type: ignore  # noqa: F401

        out["docx"] = True
    except Exception:
        out["docx"] = False
    try:
        import pypdf  # type: ignore  # noqa: F401

        out["pdf"] = True
    except Exception:
        out["pdf"] = False
    return out


def iter_parquet(path: str, batch_size: int = 50_000) -> Iterator[ExtractedUnit]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:
        raise ImportError("pyarrow required for parquet (pip install pyarrow)") from exc
    pf = pq.ParquetFile(path)
    uid = 0
    for batch in pf.iter_batches(batch_size=batch_size):
        cols = batch.schema.names
        rows = batch.to_pylist()
        for r in rows:
            uid += 1
            for c in cols:
                v = r.get(c)
                if v is None or v == "":
                    continue
                yield {"id": f"row{uid}:{c}", "text": str(v),
                       "meta": {"row": uid, "column": c}}


def iter_avro(path: str) -> Iterator[ExtractedUnit]:
    try:
        import fastavro  # type: ignore
    except Exception as exc:
        raise ImportError("fastavro required for avro (pip install fastavro)") from exc
    uid = 0
    with open(path, "rb") as fh:
        for record in fastavro.reader(fh):
            uid += 1
            for k, v in record.items():
                if v is None or v == "":
                    continue
                yield {"id": f"rec{uid}:{k}", "text": str(v),
                       "meta": {"record": uid, "field": k}}


def iter_xlsx(path: str) -> Iterator[ExtractedUnit]:
    try:
        import openpyxl  # type: ignore
    except Exception as exc:
        raise ImportError("openpyxl required for xlsx (pip install openpyxl)") from exc
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            for idx, v in enumerate(row):
                if v is None or v == "":
                    continue
                yield {"id": f"{ws.title}!{idx}", "text": str(v),
                       "meta": {"sheet": ws.title, "col": idx}}
    wb.close()


def iter_docx(path: str) -> Iterator[ExtractedUnit]:
    try:
        import docx  # type: ignore
    except Exception as exc:
        raise ImportError("python-docx required (pip install python-docx)") from exc
    doc = docx.Document(path)
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip():
            yield {"id": f"para{i}", "text": p.text, "meta": {"para": i}}
    for ti, t in enumerate(doc.tables):
        for ri, row in enumerate(t.rows):
            for ci, cell in enumerate(row.cells):
                if cell.text.strip():
                    yield {"id": f"table{ti}r{ri}c{ci}", "text": cell.text,
                           "meta": {"table": ti, "row": ri, "col": ci}}


def iter_pdf_text(path: str) -> Iterator[ExtractedUnit]:
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception as exc:
        raise ImportError("pypdf required for pdf (pip install pypdf)") from exc
    reader = PdfReader(path)
    for i, page in enumerate(reader.pages):
        try:
            txt = page.extract_text() or ""
        except Exception:
            txt = ""
        if txt.strip():
            yield {"id": f"page{i + 1}", "text": txt, "meta": {"page": i + 1}}


def iter_units(path: str, **kwargs: Any) -> Iterator[ExtractedUnit]:
    """Dispatch by extension."""
    ext = Path(path).suffix.lower().lstrip(".")
    if ext == "parquet":
        yield from iter_parquet(path, kwargs.get("batch_size", 50_000))
    elif ext == "avro":
        yield from iter_avro(path)
    elif ext == "xlsx":
        yield from iter_xlsx(path)
    elif ext in ("docx",):
        yield from iter_docx(path)
    elif ext == "pdf":
        yield from iter_pdf_text(path)
    else:
        raise ValueError(f"No extractor for .{ext}")


__all__ = [
    "ExtractedUnit",
    "available_formats",
    "iter_avro",
    "iter_docx",
    "iter_parquet",
    "iter_pdf_text",
    "iter_units",
    "iter_xlsx",
]
