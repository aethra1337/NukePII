"""NukePII production smoke test (stdlib only, no pytest).

Run:
    python scripts/smoke.py

Checks the engine + web contract without any PII fixtures: only the
checksum-spec vectors already present in the detector docstrings, plus
synthetic clean text. Exit non-zero on the first failure.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Checksum-spec vectors (also used in detector docstrings, not user data).
PAN = "4539148803436467"
PAN_BAD = "4539148803436468"
TCKN = "10000000146"
IBAN = "DE89370400440532013000"
CLEAN_TEXT = "Hello world. This file contains no personal data, just plain text.\n"


def check(name: str, cond: bool) -> None:
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(f"smoke failed: {name}")


def main() -> None:
    from nukepii.core.detectors import (
        PIIDetector,
        is_valid_iban,
        is_valid_luhn,
        is_valid_tr_national_id,
    )

    # -- checksum validators -------------------------------------------------
    check("luhn valid", is_valid_luhn(PAN) is True)
    check("luhn invalid", is_valid_luhn(PAN_BAD) is False)
    check("tckn valid", is_valid_tr_national_id(TCKN) is True)
    check("iban valid", is_valid_iban(IBAN) is True)

    # -- detector recall on spec vectors -------------------------------------
    det = PIIDetector(regions="ALL")
    types = {d["type"] for d in det.scan(f"card {PAN} id {TCKN} iban {IBAN}")}
    check("detect CREDIT_CARD", "CREDIT_CARD" in types)
    check("detect TR_NATIONAL_ID", "TR_NATIONAL_ID" in types)
    check("detect IBAN", "IBAN" in types)
    check("clean text silent", det.scan(CLEAN_TEXT) == [])

    # -- web contract (Flask test client, no server needed) ------------------
    from nukepii.web.app import create_app

    client = create_app().test_client()

    r = client.get("/api/health")
    check("health 200", r.status_code == 200 and r.get_json()["status"] == "ok")

    r = client.get("/api/v1/detectors")
    body = r.get_json()
    check("detectors catalog", r.status_code == 200 and body["count"] == 80)

    def _upload(text: str, name: str = "probe.txt"):
        return client.post(
            "/api/scan",
            data={"file": (io.BytesIO(text.encode()), name)},
            content_type="multipart/form-data",
        )

    r = _upload(CLEAN_TEXT)
    body = r.get_json()
    check("scan clean 200", r.status_code == 200 and body["total_detections"] == 0)

    r = _upload(f"payment card {PAN}\n")
    body = r.get_json()
    check("scan pan detected", r.status_code == 200 and body["total_detections"] >= 1)
    check("preview masked by default", body.get("preview_mode") == "masked")
    import json as _json

    check("no raw PAN leaks in report", PAN not in _json.dumps(body))

    r = client.post(
        "/api/clean",
        data={"file": (io.BytesIO(f"card {PAN}\n".encode()), "probe.txt")},
        content_type="multipart/form-data",
    )
    check("clean strips PAN", r.status_code == 200 and PAN.encode() not in r.data)

    # -- OpenAPI contract ------------------------------------------------------
    from nukepii.web.openapi import build_openapi

    spec = build_openapi()
    check("openapi 3.1", spec["openapi"].startswith("3.1"))
    check("openapi has v1 scan", "/api/v1/scan" in spec["paths"])

    print("smoke: all green")


if __name__ == "__main__":
    main()
