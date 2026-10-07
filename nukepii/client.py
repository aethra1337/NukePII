"""NukePII sync Python SDK (stdlib only — no extra dependencies).

Example:
    from nukepii.client import NukePIIClient

    with NukePIIClient("http://127.0.0.1:5000") as client:
        job = client.submit_scan("people.csv")
        report = client.wait_result(job["scan_id"])
        print(report["risk_score"], report["risk_label"])

Both the legacy synchronous API (``/api/scan``) and the job-oriented
v1 API (``/api/v1/*``) are covered. Timeouts raise :class:`NukePIIError`.
"""

from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class NukePIIError(RuntimeError):
    """Raised for transport errors and non-2xx API responses."""


def _encode_multipart(
    fields: dict[str, str], file_field: str, filename: str, file_bytes: bytes
) -> tuple[bytes, str]:
    boundary = f"----nukepii{int(time.time() * 1000)}"
    buf = io.BytesIO()
    for key, value in fields.items():
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        buf.write(f"{value}\r\n".encode())
    buf.write(f"--{boundary}\r\n".encode())
    buf.write(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode()
    )
    buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
    buf.write(file_bytes)
    buf.write(f"\r\n--{boundary}--\r\n".encode())
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


class NukePIIClient:
    """Minimal sync client for a running NukePII server."""

    def __init__(self, base_url: str = "http://127.0.0.1:5000", timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # -- context manager (no persistent connections; kept for ergonomics) --
    def __enter__(self) -> NukePIIClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    # -- low-level helpers -------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes, str]:
        req = urllib.request.Request(
            self.base_url + path, data=body, method=method, headers=headers or {}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return (resp.status, resp.read(), resp.headers.get_content_type())
        except urllib.error.HTTPError as exc:
            raise NukePIIError(
                f"{method} {path} -> HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:500]}"
            ) from exc
        except OSError as exc:
            raise NukePIIError(f"{method} {path} failed: {exc}") from exc

    def _json(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        status, raw, _ = self._request(method, path, body, headers)
        if status >= 400:
            raise NukePIIError(f"{method} {path} -> HTTP {status}")
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise NukePIIError(f"{method} {path}: invalid JSON") from exc

    # -- health / catalog ---------------------------------------------------
    def health(self) -> dict[str, Any]:
        return self._json("GET", "/api/v1/health")

    def detectors(self) -> dict[str, Any]:
        return self._json("GET", "/api/v1/detectors")

    def openapi(self) -> dict[str, Any]:
        return self._json("GET", "/api/openapi.json")

    # -- legacy sync scan ----------------------------------------------------
    def scan_sync(
        self, path: str | Path, mode: str = "mask", region: str = "ALL"
    ) -> dict[str, Any]:
        p = Path(path)
        body, ctype = _encode_multipart(
            {"mode": mode, "region": region}, "file", p.name, p.read_bytes()
        )
        return self._json("POST", "/api/scan", body, {"Content-Type": ctype})

    # -- v1 job flow ----------------------------------------------------------
    def submit_scan(
        self, path: str | Path, mode: str = "mask", region: str = "ALL"
    ) -> dict[str, Any]:
        p = Path(path)
        body, ctype = _encode_multipart(
            {"mode": mode, "region": region}, "file", p.name, p.read_bytes()
        )
        status, raw, _ = self._request("POST", "/api/v1/scan", body, {"Content-Type": ctype})
        if status != 202:
            raise NukePIIError(f"POST /api/v1/scan -> HTTP {status}")
        return json.loads(raw.decode("utf-8"))

    def scan_status(self, scan_id: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/scan/{urllib.parse.quote(scan_id)}/status")

    def scan_result(self, scan_id: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/scan/{urllib.parse.quote(scan_id)}/result")

    def wait_result(self, scan_id: str, timeout: float = 60.0, poll: float = 0.2) -> dict[str, Any]:
        deadline = time.time() + timeout
        while True:
            try:
                return self.scan_result(scan_id)
            except NukePIIError as exc:
                if "HTTP 409" not in str(exc):
                    raise
            if time.time() > deadline:
                raise NukePIIError(f"scan {scan_id} not done within {timeout}s")
            time.sleep(poll)

    def clean(self, scan_id: str, mode: str = "mask", region: str = "ALL") -> dict[str, Any]:
        payload = json.dumps({"scan_id": scan_id, "mode": mode, "region": region}).encode()
        return self._json("POST", "/api/v1/clean", payload, {"Content-Type": "application/json"})

    def export_file(self, scan_id: str) -> bytes:
        _, raw, _ = self._request("GET", f"/api/v1/export/{urllib.parse.quote(scan_id)}/file")
        return raw

    def export_report(self, scan_id: str) -> dict[str, Any]:
        return self._json("GET", f"/api/v1/export/{urllib.parse.quote(scan_id)}/report")


__all__ = ["NukePIIClient", "NukePIIError"]
