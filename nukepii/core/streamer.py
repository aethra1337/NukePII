"""NukePII chunk-based streaming processor for large files (1GB+).

:class:`DataStreamer` scans and sanitizes CSV / JSON / JSONL / SQL / LOG / TXT
inputs without ever loading the whole file into memory:

* **CSV** — batched row windows via Polars (``read_csv_batched``) or Pandas
  (``read_csv(chunksize=…)``), with a stdlib :mod:`csv` fallback. Backend is
  auto-selected; ``backend="stdlib"|"pandas"|"polars"`` pins it explicitly.
* **JSON** — whole-file parse below a size guard, otherwise JSONL line batches.
* **SQL / LOG / TXT** — fixed-size line batches.

Memory bound = one batch (``batch_rows`` records / ``batch_lines`` lines),
never the file size.

Public contract — identical to the ``/api/scan`` payload built by
``nukepii.web.app`` (which prefers this class and falls back to its own
reference engine only when the streamer is unavailable or errors)::

    DataStreamer().scan_file(path, mode="mask", salt=None) -> {
        "filename": str, "size_bytes": int, "engine": "streamer",
        "backend": "polars" | "pandas" | "stdlib",
        "mode": str, "region": str, "units": int,
        "unit_kind": "rows"|"records"|"lines",
        "total_detections": int, "risk_score": int (0-100),
        "risk_label": "LOW"|"MODERATE"|"HIGH"|"CRITICAL",
        "breakdown": [{"type": str, "count": int,       # count desc
                       "compliance": ["GDPR"|"KVKK"|"CCPA"]}],
        "compliance_summary": {"GDPR": int, "KVKK": int, "CCPA": int, "LGPD": int},
        "heatmap": {"kind": "columns"|"keys"|"segments",
                    "items": [{"label": str, "count": int, "risk": int}]},
        "preview": [{"line": int, "raw": str, "clean": str,
                     "spans": [{"start": int, "end": int, "type": str}]}],
        "truncated": bool,
    }

:func:`sanitize_file` (used by the CLI ``clean`` command and available to the
web layer) streams ``src -> dst`` line by line and returns run statistics.
"""

from __future__ import annotations

import csv
import json
import os
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nukepii.core.detectors import (
    PIIDetector,
    compliance_for,
    compliance_summary,
    compute_risk_score,
)
from nukepii.core.sanitizers import Sanitizer, generate_salt

try:
    import pandas as _pandas
except Exception:  # pragma: no cover - optional dependency
    _pandas = None  # type: ignore

try:
    import polars as _polars
except Exception:  # pragma: no cover - optional dependency
    _polars = None  # type: ignore


# ---------------------------------------------------------------------------
# Limits & constants (mirror nukepii.web.app so outputs stay interchangeable)
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {"csv", "json", "jsonl", "sql", "log", "txt", "md",
                      "parquet", "avro", "xlsx", "docx", "pdf"}
CLEAN_MODES = {"mask", "hash", "redact", "pseudonymize", "vault", "fpe"}

MAX_SCAN_UNITS = 200_000
PREVIEW_LIMIT = 8
PREVIEW_WIDTH = 400
SEGMENT_LINES = 200
JSON_PARSE_LIMIT = 16 * 1024 * 1024

BACKENDS = ("auto", "polars", "pandas", "stdlib")
PREVIEW_MODES = ("masked", "raw")
# Raw preview is opt-in: caller must pass preview="raw" AND allow via env
# NUKEPII_ALLOW_RAW=1 (zero-trust default = masked, no raw PII leaves engine).
RAW_PREVIEW_ENV = "NUKEPII_ALLOW_RAW"


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _extension_of(filename: str) -> str:
    suffix = Path(filename or "").suffix.lower().lstrip(".")
    return suffix if suffix in ALLOWED_EXTENSIONS else ("txt" if not suffix else suffix)


def _walk_json(obj: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (dotted key path, string value) pairs from parsed JSON.

    (Duplicated from ``nukepii.web.app`` on purpose: core must never import
    from the web layer, and this walker is stable enough to mirror.)
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                yield from _walk_json(value, path)
            elif isinstance(value, str):
                yield path, value
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                yield path, str(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_json(item, prefix)


def _heatmap_sorted(counter: Counter, order: list[str] | None = None) -> list[dict[str, Any]]:
    """Build heatmap items; chronological ``order`` preserved when given."""
    peak = max(counter.values(), default=0)

    def item(label: str) -> dict[str, Any]:
        count = counter.get(label, 0)
        return {"label": label, "count": count,
                "risk": round(100 * count / peak) if peak else 0}

    if order is not None:
        return [item(lab) for lab in order if lab in counter]
    items = [item(lab) for lab in counter]
    items.sort(key=lambda h: h["count"], reverse=True)
    return items


def _breakdown_payload(breakdown: Counter) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build ``breakdown`` items (count-desc, compliance-tagged) + framework totals."""
    items = [{"type": t, "count": breakdown[t], "compliance": compliance_for(t)}
             for t in sorted(breakdown, key=lambda t: breakdown[t], reverse=True)]
    return items, compliance_summary(dict(breakdown))


def capabilities() -> dict[str, Any]:
    """Report optional-backend availability (useful for CLI diagnostics)."""
    try:
        from nukepii.core import detectors as _det  # local import: no cycle

        _keccak = bool(getattr(_det, "_KECCAK_AVAILABLE", False))
    except Exception:
        _keccak = False
    try:
        import yaml  # type: ignore  # noqa: F401

        _yaml = True
    except Exception:
        _yaml = False
    try:
        import onnxruntime  # type: ignore  # noqa: F401

        _onnx = True
    except Exception:
        _onnx = False
    try:
        import PIL  # type: ignore  # noqa: F401

        _ocr_deps = True
    except Exception:
        _ocr_deps = False
    try:
        import pyarrow.parquet  # type: ignore  # noqa: F401

        _parquet = True
    except Exception:
        _parquet = False
    native = False
    try:
        import nukepii._native  # type: ignore  # noqa: F401

        native = True
    except Exception:
        try:
            from nukepii.core import _bridge

            native = bool(getattr(_bridge, "NATIVE_AVAILABLE", False))
        except Exception:
            native = False
    return {
        "pandas": _pandas is not None,
        "polars": _polars is not None and hasattr(_polars, "scan_csv"),
        "stdlib": True,
        "native": native,
        "keccak": _keccak,
        "yaml_rules": _yaml,
        "onnx_ner": _onnx,
        "ocr": _ocr_deps,
        "parquet": _parquet,
    }


# ---------------------------------------------------------------------------
# DataStreamer
# ---------------------------------------------------------------------------

@dataclass
class DataStreamer:
    """Chunk-streaming PII scanner/sanitizer.

    Parameters
    ----------
    salt: Default HMAC/pseudonym salt. Auto-generated per instance; pass an
        explicit salt (or per-call ``salt=``) for stable hashes across runs.
    batch_rows: CSV records per streaming batch.
    batch_lines: text lines per streaming batch (JSONL / logs).
    max_scan_units: rows/records/lines cap for :meth:`scan_file` (bounded
        latency on huge inputs; ``truncated=True`` is reported when hit).
    preview_limit / preview_width: diff-sample shape (mirrors the web API).
    backend: ``"auto"`` (polars-batched → pandas-chunked → stdlib) or a pin.
    """

    salt: str = field(default_factory=generate_salt)
    batch_rows: int = 50_000
    batch_lines: int = 10_000
    max_scan_units: int = MAX_SCAN_UNITS
    preview_limit: int = PREVIEW_LIMIT
    preview_width: int = PREVIEW_WIDTH
    backend: str = "auto"
    workers: int = 1
    preview_mode: str = "masked"

    def __post_init__(self) -> None:
        if self.backend not in BACKENDS:
            raise ValueError(f"Unknown backend {self.backend!r}. Choose from {BACKENDS}.")
        if self.preview_mode not in PREVIEW_MODES:
            raise ValueError(f"Unknown preview_mode {self.preview_mode!r}. Choose from {PREVIEW_MODES}.")
        try:
            workers = int(self.workers)
        except Exception as exc:
            raise ValueError(f"workers must be int >=1, got {self.workers!r}") from exc
        if workers < 1:
            raise ValueError(f"workers must be >=1, got {workers!r}")
        self.workers = workers
        self._detector = PIIDetector()

    # -- backend selection -------------------------------------------------

    def selected_backend(self) -> str:
        """Resolve ``"auto"`` to the best available CSV batch backend."""
        if self.backend != "auto":
            return self.backend
        caps = capabilities()
        if caps["polars"]:
            return "polars"
        if caps["pandas"]:
            return "pandas"
        return "stdlib"

    def _detector_for(self, region: str) -> PIIDetector:
        """Return the shared detector for ``"ALL"``, else a region-scoped one."""
        if isinstance(region, str) and region.upper() == "ALL":
            return self._detector
        return PIIDetector(regions=region)  # raises ValueError on bad regions

    # -- public API --------------------------------------------------------

    def scan_file(self, path: str, mode: str = "mask",
                  salt: str | None = None, region: str = "ALL",
                  preview: str | None = None) -> dict[str, Any]:
        """Scan ``path`` in bounded-memory batches -> /api/scan payload.

        ``region`` filters region-specific detectors (``"TR"``, ``"PL"``,
        ``"US"``, ``"ES"``, ``"EU"``, combinations like ``"TR,EU"``);
        ``"ALL"`` (default) enables every detector.

        ``preview``: ``"masked"`` (default, zero-trust: raw PII never leaves
        the engine, ``raw`` == sanitized ``clean``) or ``"raw"`` (legacy,
        opt-in: requires env ``NUKEPII_ALLOW_RAW=1``, else silently coerced
        to ``masked``). ``None`` falls back to the instance ``preview_mode``.
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"No such file: {path}")
        filename = Path(path).name
        ext = _extension_of(filename)
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"Unsupported file type '.{ext}'. Allowed: {sorted(ALLOWED_EXTENSIONS)}.")
        preview_mode = (preview or self.preview_mode or "masked").lower()
        if preview_mode not in PREVIEW_MODES:
            raise ValueError(f"Unknown preview mode {preview_mode!r}. Choose from {PREVIEW_MODES}.")
        preview_mode = _resolve_preview_mode(preview_mode)
        sanitizer = Sanitizer(mode=mode, salt=salt or self.salt)  # type: ignore[arg-type]
        detector = self._detector_for(region)

        if ext == "csv":
            breakdown, heat_items, units, truncated = self._scan_csv(path, detector)
            unit_kind, heat_kind = "rows", "columns"
        elif ext in ("json", "jsonl"):
            breakdown, heat_items, units, truncated = self._scan_json(path, detector)
            unit_kind, heat_kind = "records", "keys"
        else:
            breakdown, heat_items, units, truncated = self._scan_text(path, detector)
            unit_kind, heat_kind = "lines", "segments"

        total = sum(breakdown.values())
        risk_score, risk_label = compute_risk_score(dict(breakdown), units)
        breakdown_items, compliance_totals = _breakdown_payload(breakdown)
        return {
            "filename": filename,
            "size_bytes": os.path.getsize(path),
            "engine": "streamer",
            "backend": self.selected_backend(),
            "mode": mode,
            "region": region.upper(),
            "units": units,
            "unit_kind": unit_kind,
            "total_detections": total,
            "risk_score": risk_score,
            "risk_label": risk_label,
            "breakdown": breakdown_items,
            "compliance_summary": compliance_totals,
            "heatmap": {"kind": heat_kind, "items": heat_items},
            "preview": self._collect_preview(path, sanitizer, detector, preview_mode),
            "preview_mode": preview_mode,
            "raw_exposed": preview_mode == "raw",
            "workers": self.workers,
            "truncated": truncated,
        }

    def sanitize_file(self, src: str, dst: str, mode: str = "mask",
                      salt: str | None = None, region: str = "ALL") -> dict[str, Any]:
        """Stream ``src -> dst`` sanitizing PII -> run stats (bounded memory).

        CSV inputs are record-based (RFC 4180): parsed with :mod:`csv`
        so embedded newlines/quotes survive and cell boundaries are kept.
        Every other extension stays line-oriented.
        """
        if mode not in CLEAN_MODES:
            raise ValueError(f"Unknown mode {mode!r}. Allowed: {sorted(CLEAN_MODES)}.")
        if not os.path.isfile(src):
            raise FileNotFoundError(f"No such file: {src}")
        sanitizer = Sanitizer(mode=mode, salt=salt or self.salt)  # type: ignore[arg-type]
        detector = self._detector_for(region)
        ext = _extension_of(src)
        if ext == "csv":
            return self._sanitize_csv(src, dst, sanitizer, detector, mode, region)
        units = 0
        detections = 0
        with open(src, encoding="utf-8-sig", errors="replace") as fin, \
                open(dst, "w", encoding="utf-8", newline="") as fout:
            for line in fin:
                body = line.rstrip("\n")
                dets = detector.scan(body)
                detections += len(dets)
                fout.write(sanitizer.sanitize_text(body, dets) + "\n")
                units += 1
        return {
            "input": src,
            "output": dst,
            "mode": mode,
            "region": region.upper(),
            "units": units,
            "detections": detections,
            "bytes_in": os.path.getsize(src),
            "bytes_out": os.path.getsize(dst),
        }

    def _sanitize_csv(self, src: str, dst: str, sanitizer: Sanitizer,
                      detector: PIIDetector, mode: str, region: str) -> dict[str, Any]:
        """Record-based CSV sanitize: header preserved, cells sanitized."""
        units = 0
        detections = 0
        with open(src, encoding="utf-8-sig", errors="replace", newline="") as fin, \
                open(dst, "w", encoding="utf-8", newline="") as fout:
            reader = csv.reader(fin)
            writer = csv.writer(fout)
            try:
                header = next(reader)
            except StopIteration:
                return {
                    "input": src, "output": dst, "mode": mode,
                    "region": region.upper(), "units": 0, "detections": 0,
                    "bytes_in": os.path.getsize(src),
                    "bytes_out": os.path.getsize(dst),
                }
            writer.writerow(header)
            units += 1  # header counts (parity with legacy line counter)
            for row in reader:
                clean_row: list[str] = []
                for cell in row:
                    if not cell:
                        clean_row.append(cell)
                        continue
                    dets = detector.scan(cell)
                    detections += len(dets)
                    clean_row.append(sanitizer.sanitize_text(cell, dets) if dets else cell)
                writer.writerow(clean_row)
                units += 1
        return {
            "input": src,
            "output": dst,
            "mode": mode,
            "region": region.upper(),
            "units": units,
            "detections": detections,
            "bytes_in": os.path.getsize(src),
            "bytes_out": os.path.getsize(dst),
        }

    # -- CSV backends ------------------------------------------------------

    def _iter_csv_batches(self, path: str) -> Iterator[tuple[list[str], list[list[str]]]]:
        """Yield (columns, row-batch) tuples using the selected backend."""
        backend = self.selected_backend()
        if backend == "polars":
            try:
                yield from self._csv_batches_polars(path)
                return
            except Exception:
                pass  # fall through to stdlib — never break a scan on a backend quirk
        if backend == "pandas":
            try:
                yield from self._csv_batches_pandas(path)
                return
            except Exception:
                pass
        yield from self._csv_batches_stdlib(path)

    def _csv_batches_pandas(self, path: str) -> Iterator[tuple[list[str], list[list[str]]]]:
        assert _pandas is not None
        reader = _pandas.read_csv(path, chunksize=self.batch_rows, dtype=str,
                                  na_filter=False, encoding="utf-8-sig",
                                  encoding_errors="replace")
        for chunk in reader:
            columns = [str(c) for c in chunk.columns]
            rows = [[("" if v is None else str(v)) for v in row]
                    for row in chunk.values.tolist()]
            yield columns, rows

    def _csv_batches_polars(self, path: str) -> Iterator[tuple[list[str], list[list[str]]]]:
        assert _polars is not None and hasattr(_polars, "scan_csv")
        header = self._csv_header(path)
        yielded = False
        for frame in _polars.scan_csv(path).collect_batches(chunk_size=self.batch_rows):
            yielded = True
            columns = [str(c) for c in frame.columns] or header
            rows = [[("" if v is None else str(v)) for v in row]
                    for row in frame.rows()]
            yield columns, rows
        if not yielded and header:  # header-only file: no frames emitted
            yield header, []

    @staticmethod
    def _csv_header(path: str) -> list[str]:
        try:
            with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
                return next(csv.reader(fh))
        except StopIteration:
            return []

    def _csv_batches_stdlib(self, path: str) -> Iterator[tuple[list[str], list[list[str]]]]:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            try:
                columns = next(reader)
            except StopIteration:
                return
            batch: list[list[str]] = []
            for row in reader:
                batch.append(row)
                if len(batch) >= self.batch_rows:
                    yield columns, batch
                    batch = []
            if batch:
                yield columns, batch

    # -- format scanners (all bounded-memory) -------------------------------

    def _scan_batch_rows(self, columns: list[str], rows: list[list[str]],
                           scanner: PIIDetector) -> tuple[Counter, Counter]:
        breakdown: Counter = Counter()
        per_column: Counter = Counter()
        for row in rows:
            for idx in range(len(columns)):
                cell = row[idx] if idx < len(row) else ""
                if not cell:
                    continue
                for det in scanner.scan(cell):
                    breakdown[det["type"]] += 1
                    per_column[columns[idx]] += 1
        return breakdown, per_column

    def _scan_csv(self, path: str, detector: PIIDetector | None = None
                   ) -> tuple[Counter, list[dict[str, Any]], int, bool]:
        breakdown: Counter = Counter()
        per_column: Counter = Counter()
        columns: list[str] = []
        units = 0
        truncated = False
        scanner = detector or self._detector
        if self.workers > 1:
            return self._scan_csv_parallel(path, scanner)
        for cols, rows in self._iter_csv_batches(path):
            if not columns:
                columns = cols
            for row in rows:
                if units >= self.max_scan_units:
                    truncated = True
                    break
                units += 1
                for idx in range(len(columns)):
                    cell = row[idx] if idx < len(row) else ""
                    if not cell:
                        continue
                    for det in scanner.scan(cell):
                        breakdown[det["type"]] += 1
                        per_column[columns[idx]] += 1
            if truncated:
                break
        # Header columns with zero hits stay visible (parity with web engine;
        # stable sort keeps header order on count ties, exactly like it).
        peak = max(per_column.values(), default=0)
        heatmap = [
            {"label": col, "count": per_column.get(col, 0),
             "risk": round(100 * per_column.get(col, 0) / peak) if peak else 0}
            for col in columns
        ]
        heatmap.sort(key=lambda h: h["count"], reverse=True)
        return breakdown, heatmap, units, truncated

    def _scan_csv_parallel(self, path: str, scanner: PIIDetector
                           ) -> tuple[Counter, list[dict[str, Any]], int, bool]:
        """ThreadPool CSV scan (Faz-3): batches in parallel, order preserved."""
        from concurrent.futures import ThreadPoolExecutor

        breakdown: Counter = Counter()
        per_column: Counter = Counter()
        columns: list[str] = []
        units = 0
        truncated = False
        batches: list[tuple[list[str], list[list[str]]]] = list(self._iter_csv_batches(path))
        if not batches:
            return breakdown, [], 0, False
        columns = batches[0][0]
        # cap units before submitting (bounded latency preserved)
        total_rows = sum(len(rows) for _, rows in batches)
        if total_rows > self.max_scan_units:
            truncated = True
            acc = 0
            trimmed: list[tuple[list[str], list[list[str]]]] = []
            for cols, rows in batches:
                need = self.max_scan_units - acc
                if need <= 0:
                    break
                trimmed.append((cols, rows[:need]))
                acc += len(rows[:need])
            batches = trimmed
            total_rows = acc
        units = total_rows
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = [ex.submit(self._scan_batch_rows, cols, rows, scanner)
                    for cols, rows in batches]
            for f in futs:
                b, p = f.result()
                breakdown.update(b)
                per_column.update(p)
        peak = max(per_column.values(), default=0)
        heatmap = [{"label": col, "count": per_column.get(col, 0),
                    "risk": round(100 * per_column.get(col, 0) / peak) if peak else 0}
                   for col in columns]
        heatmap.sort(key=lambda h: h["count"], reverse=True)
        return breakdown, heatmap, units, truncated

    def _scan_json(self, path: str, detector: PIIDetector | None = None
                   ) -> tuple[Counter, list[dict[str, Any]], int, bool]:
        breakdown: Counter = Counter()
        per_key: Counter = Counter()
        units = 0
        truncated = False
        scanner = detector or self._detector

        def _feed(key_path: str, text: str) -> None:
            for det in scanner.scan(text):
                breakdown[det["type"]] += 1
                per_key[key_path] += 1

        if os.path.getsize(path) <= JSON_PARSE_LIMIT:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                raw = fh.read()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
            if parsed is not None:
                records = parsed if isinstance(parsed, list) else [parsed]
                for record in records:
                    if units >= self.max_scan_units:
                        truncated = True
                        break
                    units += 1
                    for key_path, text in _walk_json(record):
                        _feed(key_path, text)
                return breakdown, _heatmap_sorted(per_key), units, truncated

        batch: list[str] = []
        for line in self._iter_lines(path):
            batch.append(line)
            if len(batch) >= self.batch_lines:
                units, truncated = self._feed_json_lines(batch, breakdown, per_key, units, scanner)
                batch = []
                if truncated:
                    break
        if batch and not truncated:
            units, _ = self._feed_json_lines(batch, breakdown, per_key, units, scanner)
        return breakdown, _heatmap_sorted(per_key), units, truncated

    def _feed_json_lines(self, batch: list[str], breakdown: Counter,
                         per_key: Counter, units: int,
                         detector: PIIDetector | None = None) -> tuple[int, bool]:
        """Scan one JSONL batch; unparsable lines fall back to raw-text scan."""
        scanner = detector or self._detector
        for line in batch:
            if units >= self.max_scan_units:
                return units, True
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Same semantics as the web engine: breakdown only, no key attribution.
                for det in scanner.scan(line):
                    breakdown[det["type"]] += 1
                units += 1
                continue
            units += 1
            for key_path, text in _walk_json(record):
                for det in scanner.scan(text):
                    breakdown[det["type"]] += 1
                    per_key[key_path] += 1
        return units, False

    def _scan_text(self, path: str, detector: PIIDetector | None = None
                   ) -> tuple[Counter, list[dict[str, Any]], int, bool]:
        breakdown: Counter = Counter()
        per_segment: Counter = Counter()
        order: list[str] = []
        units = 0
        truncated = False
        scanner = detector or self._detector
        for line in self._iter_lines(path):
            if units >= self.max_scan_units:
                truncated = True
                break
            units += 1
            hits = scanner.scan(line)
            if not hits:
                continue
            seg_start = (units - 1) // SEGMENT_LINES * SEGMENT_LINES + 1
            label = f"Lines {seg_start}–{seg_start + SEGMENT_LINES - 1}"
            if label not in per_segment:
                order.append(label)
            for det in hits:
                breakdown[det["type"]] += 1
                per_segment[label] += 1
        return breakdown, _heatmap_sorted(per_segment, order=order), units, truncated

    # -- shared line iteration + preview ------------------------------------

    def _iter_lines(self, path: str) -> Iterator[str]:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\n")

    def _collect_preview(self, path: str, sanitizer: Sanitizer,
                           detector: PIIDetector | None = None,
                           preview_mode: str = "masked") -> list[dict[str, Any]]:
        preview: list[dict[str, Any]] = []
        scanner = detector or self._detector
        for line_no, line in enumerate(self._iter_lines(path), start=1):
            if len(preview) >= self.preview_limit:
                break
            dets = scanner.scan(line)
            if not dets:
                continue
            clean = sanitizer.sanitize_text(line, dets)[:self.preview_width]
            spans = [{"start": d["start"], "end": d["end"], "type": d["type"]}
                     for d in dets if d["end"] <= self.preview_width]
            if preview_mode == "raw":
                raw = line[:self.preview_width]
            else:
                # Safe preview: raw never carries open PII; UI highlights
                # masked tokens via spans remapped onto clean (best-effort:
                # rescan clean for positions, fall back to type-only spans).
                raw = clean
                spans = _remap_spans_to_clean(line, clean, dets, self.preview_width)
            preview.append({"line": line_no, "raw": raw, "clean": clean, "spans": spans})
        return preview


def _resolve_preview_mode(requested: str) -> str:
    """Coerce ``raw`` to ``masked`` unless explicitly allowed via env."""
    import os as _os

    if requested == "raw" and _os.getenv(RAW_PREVIEW_ENV, "0") != "1":
        return "masked"
    return requested


def _remap_spans_to_clean(original: str, clean: str,
                           dets: list[dict[str, Any]], width: int) -> list[dict[str, Any]]:
    """Best-effort span remap so UI can highlight masked tokens safely.

    Re-scans ``clean`` for masked placeholders would be expensive; instead
    keep (type) + clamp offsets into ``clean`` bounds. Positions may shift
    when hash mode changes length — clients must treat spans as hints.
    """
    out: list[dict[str, Any]] = []
    n = min(len(clean), width)
    for d in dets:
        s, e = int(d["start"]), int(d["end"])
        if s >= width:
            continue
        out.append({"start": min(s, max(n - 1, 0)), "end": min(e, n),
                    "type": d["type"]})
    return out


__all__ = [
    "ALLOWED_EXTENSIONS",
    "BACKENDS",
    "CLEAN_MODES",
    "MAX_SCAN_UNITS",
    "PREVIEW_LIMIT",
    "PREVIEW_MODES",
    "PREVIEW_WIDTH",
    "SEGMENT_LINES",
    "DataStreamer",
    "capabilities",
]
