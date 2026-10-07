"""NukePII Flask web dashboard + REST API.

Routes
------
* ``GET /``            — landing page with drag-and-drop upload zone.
* ``GET /dashboard``   — interactive visualization shell (Chart.js, data via API).
* ``GET /api/health``  — liveness probe (engine info, no file handling).
* ``POST /api/scan``   — multipart file upload -> JSON risk report
  (risk score, breakdown, heatmap, preview diff sample).
* ``POST /api/clean``  —multipart file upload + ``mode`` -> sanitized file download.

Zero-Trust / local-first notes
------------------------------
* Uploads are streamed to a temp file (never kept in RAM); scanning reads the
  temp file lazily, line by line, so multi-GB inputs stay memory-bounded.
* API responses carry ``Cache-Control: no-store`` — scan reports contain raw
  PII excerpts and must never be cached by browsers/proxies.
* File contents are never logged. Temp files are unlinked in ``finally`` blocks.
* Filename handling uses :func:`werkzeug.utils.secure_filename` and an
  extension allowlist (CSV, JSON/JSONL, SQL, LOG, TXT).

Streamer integration
--------------------
The scan path prefers ``nukepii.core.streamer.DataStreamer`` when it exposes
the documented ``scan_file()`` contract; otherwise (and on any streamer
error) it falls back to the built-in chunked scanner below, which uses the
same :class:`PIIDetector` / :class:`Sanitizer` core. Both paths return the
identical ``/api/scan`` JSON contract.
"""

from __future__ import annotations

import contextlib
import csv
import json
import os
import tempfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from werkzeug.utils import secure_filename

from nukepii import __version__

try:  # Phase-2 streamer is optional at runtime; local engine is the fallback.
    from nukepii.core.streamer import DataStreamer  # type: ignore
    _HAS_STREAMER = True
except Exception:  # ImportError or any streamer init-time failure.
    DataStreamer = None  # type: ignore
    _HAS_STREAMER = False

from nukepii.core.detectors import (
    REGIONS,
    PIIDetector,
    compliance_for,
    compliance_summary,
    compute_risk_score,
)
from nukepii.core.sanitizers import Sanitizer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {"csv", "json", "jsonl", "sql", "log", "txt", "md",
                      "parquet", "avro", "xlsx", "docx", "pdf"}
CLEAN_MODES = {"mask", "hash", "redact", "pseudonymize", "vault", "fpe"}
SCAN_MODES = CLEAN_MODES | {"noise"}  # "noise" accepted; applies where relevant

def _max_upload_bytes() -> int:
    """Upload cap in bytes, overridable via ``NUKEPII_MAX_MB`` (default 256)."""
    try:
        mb = int(os.getenv("NUKEPII_MAX_MB", "256"))
    except ValueError:
        mb = 256
    return max(1, mb) * 1024 * 1024


MAX_CONTENT_LENGTH = _max_upload_bytes()
MAX_SCAN_UNITS = 200_000                 # rows/records/lines cap for /api/scan
PREVIEW_LIMIT = 8                        # diff rows returned by /api/scan
PREVIEW_WIDTH = 400                      # chars per preview cell
SEGMENT_LINES = 200                      # heatmap window for line-oriented files
JSON_PARSE_LIMIT = 16 * 1024 * 1024      # whole-file json.loads only below this
PREVIEW_MODES = ("masked", "raw")
RAW_PREVIEW_ENV = "NUKEPII_ALLOW_RAW"


def _resolve_preview_mode(requested: str) -> str:
    requested = (requested or "masked").lower()
    if requested not in PREVIEW_MODES:
        return "masked"
    if requested == "raw" and os.getenv(RAW_PREVIEW_ENV, "0") != "1":
        return "masked"
    return requested


# ---------------------------------------------------------------------------
# Risk scoring (single source of truth lives in nukepii.core.detectors)
# ---------------------------------------------------------------------------

def compute_risk(breakdown: Counter, units: int) -> tuple[int, str]:
    """Backwards-compatible alias of :func:`compute_risk_score` (accepts Counter)."""
    return compute_risk_score(dict(breakdown), units)


# ---------------------------------------------------------------------------
# Local chunked scan engine (fallback / reference implementation)
# ---------------------------------------------------------------------------

def _extension_of(filename: str) -> str:
    suffix = Path(filename or "").suffix.lower().lstrip(".")
    return suffix if suffix in ALLOWED_EXTENSIONS else ("txt" if not suffix else suffix)


def _iter_lines(path: str) -> Iterator[str]:
    """Yield file lines lazily (bounded memory regardless of file size)."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n")


def _walk_json(obj: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (dotted key path, string value) pairs from parsed JSON."""
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


def _scan_csv(path: str, detector: PIIDetector
              ) -> tuple[Counter, list[dict[str, Any]], int, bool]:
    """Stream a CSV: returns (breakdown, heatmap_items, units, truncated)."""
    breakdown: Counter = Counter()
    per_column: Counter = Counter()
    columns: list[str] = []
    units = 0
    truncated = False
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        try:
            columns = next(reader)
        except StopIteration:
            return breakdown, [], 0, False
        n_cols = len(columns)
        for row in reader:
            if units >= MAX_SCAN_UNITS:
                truncated = True
                break
            units += 1
            for idx in range(n_cols):
                cell = row[idx] if idx < len(row) else ""
                if not cell:
                    continue
                for det in detector.scan(cell):
                    breakdown[det["type"]] += 1
                    per_column[columns[idx]] += 1
    peak = max(per_column.values(), default=0)
    heatmap = [
        {"label": col,
         "count": per_column.get(col, 0),
         "risk": round(100 * per_column.get(col, 0) / peak) if peak else 0}
        for col in columns
    ]
    heatmap.sort(key=lambda h: h["count"], reverse=True)
    return breakdown, heatmap, units, truncated


def _scan_json(path: str, detector: PIIDetector
               ) -> tuple[Counter, list[dict[str, Any]], int, bool]:
    """Scan JSON (whole-file or JSONL): (breakdown, heatmap_items, units, truncated)."""
    breakdown: Counter = Counter()
    per_key: Counter = Counter()
    units = 0
    truncated = False
    size = os.path.getsize(path)

    def _feed(value_path: str, text: str) -> None:
        for det in detector.scan(text):
            breakdown[det["type"]] += 1
            per_key[value_path] += 1

    if size <= JSON_PARSE_LIMIT:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            raw = fh.read()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            records = parsed if isinstance(parsed, list) else [parsed]
            for record in records:
                if units >= MAX_SCAN_UNITS:
                    truncated = True
                    break
                units += 1
                for key_path, text in _walk_json(record):
                    _feed(key_path, text)
            return breakdown, _heatmap_from(per_key), units, truncated
        # Not whole-file JSON -> fall through to JSONL attempt below.

    for line in _iter_lines(path):
        if units >= MAX_SCAN_UNITS:
            truncated = True
            break
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            for det in detector.scan(line):  # plain-text fallback for this line
                breakdown[det["type"]] += 1
            units += 1
            continue
        units += 1
        for key_path, text in _walk_json(record):
            _feed(key_path, text)
    return breakdown, _heatmap_from(per_key), units, truncated


def _heatmap_from(counter: Counter) -> list[dict[str, Any]]:
    peak = max(counter.values(), default=0)
    items = [{"label": k, "count": v,
              "risk": round(100 * v / peak) if peak else 0}
             for k, v in counter.items()]
    items.sort(key=lambda h: h["count"], reverse=True)
    return items


def _scan_text_segments(path: str, detector: PIIDetector
                        ) -> tuple[Counter, list[dict[str, Any]], int, bool]:
    """Scan line-oriented files (SQL/LOG/TXT): heatmap = line windows."""
    breakdown: Counter = Counter()
    per_segment: Counter = Counter()
    units = 0
    truncated = False
    for line in _iter_lines(path):
        if units >= MAX_SCAN_UNITS:
            truncated = True
            break
        units += 1
        hits = detector.scan(line)
        if not hits:
            continue
        seg_start = (units - 1) // SEGMENT_LINES * SEGMENT_LINES + 1
        label = f"Lines {seg_start}–{seg_start + SEGMENT_LINES - 1}"
        for det in hits:
            breakdown[det["type"]] += 1
            per_segment[label] += 1
    # Preserve segment order (chronological) rather than sorting by count.
    peak = max(per_segment.values(), default=0)
    seen: list[str] = []
    for line_no in range(1, units + 1, SEGMENT_LINES):
        label = f"Lines {line_no}–{line_no + SEGMENT_LINES - 1}"
        if label in per_segment and label not in seen:
            seen.append(label)
    heatmap = [{"label": lab, "count": per_segment[lab],
                "risk": round(100 * per_segment[lab] / peak) if peak else 0}
               for lab in seen]
    return breakdown, heatmap, units, truncated


def _collect_preview(path: str, detector: PIIDetector, sanitizer: Sanitizer,
                     preview_mode: str = "masked") -> list[dict[str, Any]]:
    """First PREVIEW_LIMIT lines containing PII (Safe Preview by default)."""
    preview: list[dict[str, Any]] = []
    for line_no, line in enumerate(_iter_lines(path), start=1):
        if len(preview) >= PREVIEW_LIMIT:
            break
        dets = detector.scan(line)
        if not dets:
            continue
        clean = sanitizer.sanitize_text(line, dets)[:PREVIEW_WIDTH]
        if preview_mode == "raw":
            raw = line[:PREVIEW_WIDTH]
            spans = [{"start": d["start"], "end": d["end"], "type": d["type"]}
                     for d in dets if d["end"] <= PREVIEW_WIDTH]
        else:
            raw = clean
            n = len(clean)
            spans = [{"start": min(int(d["start"]), max(n - 1, 0)),
                      "end": min(int(d["end"]), n), "type": d["type"]}
                     for d in dets if int(d["start"]) < PREVIEW_WIDTH]
        preview.append({"line": line_no, "raw": raw, "clean": clean, "spans": spans})
    return preview


def _breakdown_payload(breakdown: Counter) -> tuple[list[dict[str, object]], dict[str, int]]:
    """Build ``breakdown`` items (count-desc, compliance-tagged) + framework totals."""
    items = [{"type": t, "count": breakdown[t], "compliance": compliance_for(t)}
             for t in sorted(breakdown, key=lambda t: breakdown[t], reverse=True)]
    return items, compliance_summary(dict(breakdown))


def scan_file_local(path: str, filename: str, mode: str = "mask",
                    salt: str | None = None, region: str = "ALL",
                    preview: str = "masked") -> dict[str, Any]:
    """Run the built-in chunked scan; returns the /api/scan JSON payload."""
    from nukepii.core.sanitizers import generate_salt
    preview_mode = _resolve_preview_mode(preview)
    detector = PIIDetector(regions=region)  # raises ValueError on bad regions
    sanitizer = Sanitizer(mode=mode, salt=salt or generate_salt())  # type: ignore[arg-type]
    ext = _extension_of(filename)

    if ext == "csv":
        breakdown, heatmap_items, units, truncated = _scan_csv(path, detector)
        unit_kind, heat_kind = "rows", "columns"
    elif ext in ("json", "jsonl"):
        breakdown, heatmap_items, units, truncated = _scan_json(path, detector)
        unit_kind, heat_kind = "records", "keys"
    else:
        breakdown, heatmap_items, units, truncated = _scan_text_segments(path, detector)
        unit_kind, heat_kind = "lines", "segments"

    total = sum(breakdown.values())
    risk_score, risk_label = compute_risk(breakdown, units)
    breakdown_items, compliance_totals = _breakdown_payload(breakdown)
    result: dict[str, Any] = {
        "filename": Path(filename).name,
        "size_bytes": os.path.getsize(path),
        "engine": "local",
        "mode": mode,
        "region": region.upper(),
        "units": units,
        "unit_kind": unit_kind,
        "total_detections": total,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "breakdown": breakdown_items,
        "compliance_summary": compliance_totals,
        "heatmap": {"kind": heat_kind, "items": heatmap_items},
        "preview": _collect_preview(path, detector, sanitizer, preview_mode),
        "preview_mode": preview_mode,
        "raw_exposed": preview_mode == "raw",
        "truncated": truncated,
    }
    return result


def _try_streamer_scan(path: str, filename: str, mode: str,
                       salt: str | None, region: str = "ALL",
                       preview: str = "masked") -> dict[str, Any] | None:
    """Attempt a Phase-2 streamer scan; ``None`` when unavailable/incompatible."""
    if not _HAS_STREAMER or DataStreamer is None:
        return None
    try:
        streamer = DataStreamer()  # type: ignore[operator]
        scan_fn = getattr(streamer, "scan_file", None)
        if not callable(scan_fn):
            return None
        try:
            payload = scan_fn(path, mode=mode, salt=salt, region=region, preview=preview)
        except TypeError:
            payload = scan_fn(path, mode=mode, salt=salt, region=region)
        if not isinstance(payload, dict) or "breakdown" not in payload:
            return None
        payload.setdefault("engine", "streamer")
        # scan_file only sees the temp path, so restore the real upload name.
        payload["filename"] = Path(filename).name
        return payload
    except Exception:
        return None  # never break the web path on a streamer regression


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------

def _register_page(app: Flask, page: str) -> None:
    """Serve ``GET /<page>`` from ``templates/<page>.html`` (no file handling)."""

    def _view() -> str:
        return render_template(f"{page}.html", version=__version__)

    _view.__name__ = f"page_{page}"
    app.add_url_rule(f"/{page}", endpoint=f"page_{page}",
                     view_func=_view, methods=["GET"])

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    @app.after_request
    def _secure(resp: Response) -> Response:
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    # -- pages -----------------------------------------------------------

    @app.get("/")
    def index() -> str:
        return render_template(
            "index.html",
            version=__version__,
            engine="streamer" if _HAS_STREAMER else "local",
            allowed=sorted(ALLOWED_EXTENSIONS),
            max_mb=MAX_CONTENT_LENGTH // (1024 * 1024),
        )

    @app.get("/dashboard")
    def dashboard() -> str:
        return render_template("dashboard.html", version=__version__)

    # -- section pages (templates ship with the app; one route each) ---
    for _page in ("scan", "analysis", "clean", "export", "history",
                  "detectors", "settings", "faq", "manual", "guide"):
        _register_page(app, _page)

    # -- API v1 --------------------------------------------------------
    from nukepii.web.api_v1 import api_v1
    app.register_blueprint(api_v1, url_prefix="/api/v1")

    # -- OpenAPI contract + docs (served locally, no upload handling) --
    @app.get("/api/openapi.json")
    def openapi_json() -> Response:
        from nukepii.web.openapi import build_openapi

        resp = jsonify(build_openapi())
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/api/docs")
    def api_docs() -> Response:
        from nukepii.web.openapi import DOCS_HTML

        resp = Response(DOCS_HTML, mimetype="text/html")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/api/health")
    def health() -> Response:
        resp = jsonify({"status": "ok", "version": __version__,
                        "engine": "streamer" if _HAS_STREAMER else "local"})
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # -- API: scan -------------------------------------------------------

    @app.post("/api/scan")
    def api_scan() -> Response:
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return _err("No file part in request (field name must be 'file').", 400)
        ext = _extension_of(upload.filename)
        if ext not in ALLOWED_EXTENSIONS:
            return _err(f"Unsupported file type '.{ext}'. "
                        f"Allowed: {sorted(ALLOWED_EXTENSIONS)}.", 400)
        mode = (request.form.get("mode") or "mask").lower()
        if mode not in SCAN_MODES:
            return _err(f"Unknown mode {mode!r}. Allowed: {sorted(SCAN_MODES)}.", 400)
        salt = request.form.get("salt") or None
        region = (request.args.get("region") or request.form.get("region") or "ALL").upper()
        if region not in REGIONS:
            return _err(f"Unknown region {region!r}. Allowed: {list(REGIONS)}.", 400)
        preview_req = (request.args.get("preview") or request.form.get("preview") or "masked").lower()
        if preview_req not in PREVIEW_MODES:
            return _err(f"Unknown preview {preview_req!r}. Allowed: {list(PREVIEW_MODES)}.", 400)
        preview_mode = _resolve_preview_mode(preview_req)

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}")
        try:
            upload.save(tmp.name)
            tmp.close()
            result = _try_streamer_scan(tmp.name, upload.filename, mode, salt, region, preview_mode)
            if result is None:
                result = scan_file_local(tmp.name, upload.filename, mode, salt, region, preview_mode)
            resp = jsonify(result)
            resp.headers["Cache-Control"] = "no-store"
            return resp
        finally:
            _silent_unlink(tmp.name)

    # -- API: clean (streamed download) ----------------------------------

    @app.post("/api/clean")
    def api_clean() -> Response:
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return _err("No file part in request (field name must be 'file').", 400)
        ext = _extension_of(upload.filename)
        if ext not in ALLOWED_EXTENSIONS:
            return _err(f"Unsupported file type '.{ext}'. "
                        f"Allowed: {sorted(ALLOWED_EXTENSIONS)}.", 400)
        mode = (request.form.get("mode") or "mask").lower()
        if mode not in CLEAN_MODES:
            return _err(f"Unknown mode {mode!r}. Allowed: {sorted(CLEAN_MODES)}.", 400)
        salt = request.form.get("salt") or None
        region = (request.args.get("region") or request.form.get("region") or "ALL").upper()
        if region not in REGIONS:
            return _err(f"Unknown region {region!r}. Allowed: {list(REGIONS)}.", 400)

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}")
        upload.save(tmp.name)
        tmp.close()

        from nukepii.core.sanitizers import generate_salt
        detector = PIIDetector(regions=region)
        sanitizer = Sanitizer(mode=mode, salt=salt or generate_salt())  # type: ignore[arg-type]
        out_name = secure_filename(f"{Path(upload.filename).stem}.nukepii.{ext}")

        def generate() -> Iterator[str]:
            try:
                with open(tmp.name, encoding="utf-8-sig", errors="replace") as fh:
                    for line in fh:
                        body = line.rstrip("\n")
                        dets = detector.scan(body)
                        yield sanitizer.sanitize_text(body, dets) + "\n"
            finally:
                _silent_unlink(tmp.name)

        headers = {"Content-Disposition": f'attachment; filename="{out_name}"',
                   "Cache-Control": "no-store"}
        return Response(stream_with_context(generate()),
                        mimetype="application/octet-stream", headers=headers)

    # -- API: report (audit HTML/PDF, Safe Preview: never raw PII) --------

    @app.post("/api/report")
    def api_report() -> Response:
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return _err("No file part in request (field name must be 'file').", 400)
        ext = _extension_of(upload.filename)
        if ext not in ALLOWED_EXTENSIONS:
            return _err(f"Unsupported file type '.{ext}'.", 400)
        fmt = (request.form.get("format") or "html").lower()
        if fmt not in ("html", "pdf"):
            return _err("format must be html|pdf.", 400)
        region = (request.args.get("region") or request.form.get("region") or "ALL").upper()
        if region not in REGIONS:
            return _err(f"Unknown region {region!r}.", 400)
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}")
        try:
            upload.save(tmp.name)
            tmp.close()
            result = _try_streamer_scan(tmp.name, upload.filename, "mask", None, region, "masked")
            if result is None:
                result = scan_file_local(tmp.name, upload.filename, "mask", None, region, "masked")
            from nukepii.web.report import build_html, build_pdf

            if fmt == "pdf":
                try:
                    pdf = build_pdf(result)
                except ImportError as exc:
                    return _err(str(exc), 501)
                headers = {"Content-Disposition": 'attachment; filename="nukepii-report.pdf"',
                           "Cache-Control": "no-store"}
                return Response(pdf, mimetype="application/pdf", headers=headers)
            resp = Response(build_html(result), mimetype="text/html")
            resp.headers["Cache-Control"] = "no-store"
            return resp
        finally:
            _silent_unlink(tmp.name)

    @app.errorhandler(413)
    def too_large(_e: Exception) -> Response:
        return _err(f"File exceeds the {MAX_CONTENT_LENGTH // (1024 * 1024)} MB limit.", 413)

    return app


def _err(message: str, status: int) -> Response:
    resp = jsonify({"error": message})
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _silent_unlink(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


if __name__ == "__main__":  # pragma: no cover
    create_app().run(host=os.getenv("NUKEPII_HOST", "127.0.0.1"),
                     port=int(os.getenv("NUKEPII_PORT", "5000")),
                     debug=os.getenv("NUKEPII_DEBUG") == "1")
