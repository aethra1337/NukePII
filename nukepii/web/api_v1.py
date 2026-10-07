"""NukePII REST API v1 — scan-job oriented endpoints (local-first).

All state lives in this process (in-memory job store + temp files); nothing
leaves the machine. Every response carries ``Cache-Control: no-store`` because
payloads may reference PII file names and masked excerpts.

Masking guarantee: the ``result`` payload only ever contains the Safe Preview
(``preview_mode`` resolved exactly like the legacy ``/api/scan`` route —
``masked`` unless ``preview=raw`` was explicitly requested *and* the
``NUKEPII_ALLOW_RAW=1`` belt is set). No raw file bytes are ever returned.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import tempfile
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, jsonify, request
from werkzeug.utils import secure_filename

from nukepii import __version__
from nukepii.core.detectors import (
    REGION_OF_TYPE,
    SEVERITY_WEIGHTS,
    PIIDetector,
    compliance_for,
)

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")

MAX_JOBS = 20
# v1 clean keeps the sanitized copy in-process (job store) so it can be
# downloaded via /export; bound it to avoid unbounded memory growth per job.
# Larger files should use the streaming legacy POST /api/clean endpoint.
MAX_V1_CLEAN_BYTES = 64 * 1024 * 1024

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

# ---------------------------------------------------------------------------
# Request / response models (dataclasses — the v1 contract)
# ---------------------------------------------------------------------------

@dataclass
class ScanStatus:
    scan_id: str
    status: str  # queued | running | done | error
    progress: int  # 0-100 (coarse: queued=0, running=50, done=100)
    filename: str = ""


@dataclass
class DetectorInfo:
    type: str
    description: str
    region: str
    compliance: list[str]
    severity: float
    confidence: float


@dataclass
class HealthInfo:
    status: str = "ok"
    version: str = __version__
    engine: str = "local"


@dataclass
class _Job:
    scan_id: str
    filename: str
    tmp_path: str
    mode: str
    region: str
    salt: str | None
    preview: str
    status: str = "queued"
    progress: int = 0
    result: dict[str, Any] | None = None
    error: str = ""
    cleaned: bytes = b""
    cleaned_name: str = ""


_JOBS: dict[str, _Job] = {}
_JOBS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Helpers (deferred app imports avoid a circular import at module load)
# ---------------------------------------------------------------------------

def _limits() -> tuple[set[str], set[str], set[str]]:
    from nukepii.core.detectors import REGIONS
    from nukepii.web.app import ALLOWED_EXTENSIONS, CLEAN_MODES

    return set(ALLOWED_EXTENSIONS), set(CLEAN_MODES), set(REGIONS)


def _err(message: str, status: int) -> Response:
    resp = jsonify({"error": message})
    resp.status_code = status
    return resp


def _get_job(scan_id: str) -> _Job | None:
    with _JOBS_LOCK:
        return _JOBS.get(scan_id)


def _store_job(job: _Job) -> None:
    with _JOBS_LOCK:
        _JOBS[job.scan_id] = job
        # Evict oldest finished jobs beyond the cap (never evict running ones).
        if len(_JOBS) > MAX_JOBS:
            for sid, old in list(_JOBS.items()):
                if len(_JOBS) <= MAX_JOBS:
                    break
                if old.status in ("done", "error"):
                    with contextlib.suppress(OSError):
                        os.unlink(old.tmp_path)
                    del _JOBS[sid]


def _run_scan(scan_id: str) -> None:
    """Background worker: temp file -> report payload (masked preview)."""
    from nukepii.web.app import _try_streamer_scan, scan_file_local

    job = _get_job(scan_id)
    if job is None:
        return
    job.status = "running"
    job.progress = 50
    try:
        payload = _try_streamer_scan(job.tmp_path, job.filename, job.mode,
                                     job.salt, job.region, job.preview)
        if payload is None:
            payload = scan_file_local(job.tmp_path, job.filename, job.mode,
                                      job.salt, job.region, job.preview)
        payload["scan_id"] = scan_id
        job.result = payload
        job.status = "done"
        job.progress = 100
    except Exception as exc:  # never leak tracebacks; report the error
        job.status = "error"
        job.error = str(exc) or "scan failed"


@api_v1.after_request
def _no_store(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store"
    for key, value in _SECURITY_HEADERS.items():
        resp.headers.setdefault(key, value)
    return resp


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@api_v1.get("/health")
def health() -> Response:
    try:
        from nukepii.core.streamer import DataStreamer  # noqa: F401

        engine = "streamer"
    except Exception:
        engine = "local"
    return jsonify(asdict(HealthInfo(engine=engine)))


@api_v1.get("/detectors")
def detectors() -> Response:
    from nukepii.core.detectors import PII_TYPES

    # _regex_specs covers pure-regex secrets; the remaining PII_TYPES are
    # regex-candidate + checksum-validated (Luhn, Mod10/11, Mod97, ...).
    descriptions = {s.pii_type: (s.description, s.confidence)
                    for s in PIIDetector(regions="ALL")._regex_specs}
    items = [
        asdict(DetectorInfo(
            type=t,
            description=descriptions.get(t, (f"{t} (checksum-validated)", 0.95))[0],
            region=REGION_OF_TYPE.get(t, "GLOBAL"),
            compliance=compliance_for(t),
            severity=SEVERITY_WEIGHTS.get(t, 1.0),
            confidence=descriptions.get(t, ("", 0.95))[1],
        ))
        for t in sorted(set(PII_TYPES))
    ]
    return jsonify({"count": len(items), "detectors": items})


@api_v1.post("/scan")
def scan() -> Response:
    allowed, clean_modes, regions = _limits()
    from nukepii.web.app import _extension_of

    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return _err("No file part in request (field name must be 'file').", 400)
    ext = _extension_of(upload.filename)
    if ext not in allowed:
        return _err(f"Unsupported file type '.{ext}'. Allowed: {sorted(allowed)}.", 400)
    mode = (request.form.get("mode") or "mask").lower()
    if mode not in clean_modes and mode != "noise":
        return _err(f"Unknown mode {mode!r}.", 400)
    region = (request.form.get("region") or "ALL").upper()
    if region not in regions:
        return _err(f"Unknown region {region!r}.", 400)
    preview = (request.form.get("preview") or "masked").lower()
    if preview not in ("masked", "raw"):
        return _err("preview must be masked|raw.", 400)
    salt = request.form.get("salt") or None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tmp:
            upload.save(tmp.name)
            tmp_path = tmp.name
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp.name)
        raise
    # 128-bit random job id (unpredictable; not a capability secret, but must
    # not be enumerable across the shared in-process job store).
    job = _Job(scan_id=secrets.token_hex(16), filename=Path(upload.filename).name,
               tmp_path=tmp_path, mode=mode, region=region, salt=salt,
               preview=preview)
    _store_job(job)
    thread = threading.Thread(target=_run_scan, args=(job.scan_id,), daemon=True)
    thread.start()
    resp = jsonify(asdict(ScanStatus(job.scan_id, "queued", 0, job.filename)))
    resp.status_code = 202
    return resp


@api_v1.get("/scan/<scan_id>/status")
def scan_status(scan_id: str) -> Response:
    job = _get_job(scan_id)
    if job is None:
        return _err(f"Unknown scan_id {scan_id!r}.", 404)
    return jsonify(asdict(ScanStatus(job.scan_id, job.status, job.progress,
                                     job.filename)))


@api_v1.get("/scan/<scan_id>/result")
def scan_result(scan_id: str) -> Response:
    job = _get_job(scan_id)
    if job is None:
        return _err(f"Unknown scan_id {scan_id!r}.", 404)
    if job.status != "done" or job.result is None:
        resp = jsonify({"scan_id": scan_id, "status": job.status,
                        "progress": job.progress,
                        **({"error": job.error} if job.error else {})})
        resp.status_code = 409
        return resp
    return jsonify(job.result)


@api_v1.post("/clean")
def clean() -> Response:
    _allowed, _clean_modes, _regions = _limits()
    data = request.get_json(silent=True) or {}
    scan_id = str(data.get("scan_id") or "")
    job = _get_job(scan_id) if scan_id else None
    if job is None:
        return _err("Unknown scan_id. Run POST /api/v1/scan first.", 404)
    if job.status != "done":
        return _err(f"Scan {scan_id!r} is {job.status}; result not ready.", 409)
    mode = str(data.get("mode") or job.mode).lower()
    if mode not in _clean_modes:
        return _err(f"Unknown mode {mode!r}. Allowed: {sorted(_clean_modes)}.", 400)
    region = str(data.get("region") or job.region).upper()
    if region not in _regions:
        return _err(f"Unknown region {region!r}.", 400)
    salt = data.get("salt", job.salt) or None
    try:
        if os.path.getsize(job.tmp_path) > MAX_V1_CLEAN_BYTES:
            return _err(
                f"Scan file exceeds the v1 clean limit "
                f"({MAX_V1_CLEAN_BYTES // (1024 * 1024)} MB in-process). "
                f"Use streaming POST /api/clean instead.",
                413,
            )
    except OSError:
        return _err("Scan file is no longer available.", 410)

    from nukepii.core.detectors import PIIDetector
    from nukepii.core.sanitizers import Sanitizer, generate_salt

    detector = PIIDetector(regions=region)
    sanitizer = Sanitizer(mode=mode, salt=salt or generate_salt())  # type: ignore[arg-type]
    out_lines: list[str] = []
    detections = 0
    with open(job.tmp_path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            body = line.rstrip("\n")
            dets = detector.scan(body)
            detections += len(dets)
            out_lines.append(sanitizer.sanitize_text(body, dets))
    stem = Path(job.filename).stem
    ext = Path(job.filename).suffix.lstrip(".") or "txt"
    job.cleaned = ("\n".join(out_lines) + "\n").encode("utf-8")
    job.cleaned_name = secure_filename(f"{stem}.nukepii.{ext}")
    return jsonify({"scan_id": scan_id, "mode": mode, "region": region,
                    "filename": job.cleaned_name,
                    "size_bytes": len(job.cleaned), "detections": detections})


@api_v1.get("/export/<scan_id>/file")
def export_file(scan_id: str) -> Response:
    job = _get_job(scan_id)
    if job is None:
        return _err(f"Unknown scan_id {scan_id!r}.", 404)
    if not job.cleaned:
        return _err(f"Scan {scan_id!r} has no cleaned output. POST /api/v1/clean first.", 409)
    headers = {"Content-Disposition": f'attachment; filename="{job.cleaned_name}"'}
    return Response(job.cleaned, mimetype="application/octet-stream",
                    headers=headers)


@api_v1.get("/export/<scan_id>/report")
def export_report(scan_id: str) -> Response:
    import json

    job = _get_job(scan_id)
    if job is None:
        return _err(f"Unknown scan_id {scan_id!r}.", 404)
    if job.status != "done" or job.result is None:
        return _err(f"Scan {scan_id!r} is {job.status}; result not ready.", 409)
    body = json.dumps(job.result, indent=2).encode("utf-8")
    headers = {"Content-Disposition":
               f'attachment; filename="{Path(job.filename).stem}.nukepii-report.json"'}
    return Response(body, mimetype="application/json", headers=headers)


__all__ = ["DetectorInfo", "HealthInfo", "ScanStatus", "api_v1"]
