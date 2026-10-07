"""OpenAPI 3.1 document for the NukePII HTTP API (stdlib only).

Single source of truth for:
* ``GET /api/openapi.json`` (served by the Flask app),
* ``GET /api/docs`` (Swagger-UI shell pointing at the JSON above),
* ``nukepii openapi --out openapi.json`` (offline export for SDK/CI).

Covers both the legacy synchronous routes (``/api/scan``, ``/api/clean``,
``/api/report``, ``/api/health``) and the job-oriented ``/api/v1/*`` set.
"""

from __future__ import annotations

from typing import Any

from nukepii import __version__


def build_openapi() -> dict[str, Any]:
    file_param = {
        "name": "file",
        "in": "formData",
        "required": True,
        "schema": {"type": "string", "format": "binary"},
        "description": "File to scan (csv/json/jsonl/sql/log/txt/md/parquet/avro/xlsx/docx/pdf).",
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "NukePII API",
            "version": __version__,
            "description": "Zero-Trust, local-first PII detection & sanitization. "
            "All state stays in-process; responses carry "
            "`Cache-Control: no-store`.",
            "license": {"name": "MIT"},
        },
        "servers": [{"url": "http://127.0.0.1:5000", "description": "Local Flask dev server"}],
        "tags": [
            {"name": "health", "description": "Liveness probes."},
            {"name": "scan", "description": "Synchronous scan/clean/report."},
            {"name": "v1", "description": "Job-oriented async scan flow."},
        ],
        "paths": {
            "/api/health": {
                "get": {
                    "tags": ["health"],
                    "summary": "Liveness probe (legacy).",
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/api/scan": {
                "post": {
                    "tags": ["scan"],
                    "summary": "Scan an uploaded file, return the risk report (sync).",
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"},
                                        "mode": {"type": "string", "default": "mask"},
                                        "region": {"type": "string", "default": "ALL"},
                                        "preview": {
                                            "type": "string",
                                            "enum": ["masked", "raw"],
                                            "default": "masked",
                                        },
                                        "salt": {"type": "string"},
                                    },
                                    "required": ["file"],
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Risk report JSON"},
                        "400": {"description": "Bad request"},
                        "413": {"description": "File too large"},
                    },
                }
            },
            "/api/clean": {
                "post": {
                    "tags": ["scan"],
                    "summary": "Sanitize an uploaded file, stream the cleaned copy.",
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"},
                                        "mode": {"type": "string", "default": "mask"},
                                        "region": {"type": "string", "default": "ALL"},
                                        "salt": {"type": "string"},
                                    },
                                    "required": ["file"],
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Sanitized file bytes"},
                        "400": {"description": "Bad request"},
                    },
                }
            },
            "/api/report": {
                "post": {
                    "tags": ["scan"],
                    "summary": "Audit report (HTML, or PDF when WeasyPrint present).",
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"},
                                        "format": {
                                            "type": "string",
                                            "enum": ["html", "pdf"],
                                            "default": "html",
                                        },
                                        "region": {"type": "string", "default": "ALL"},
                                    },
                                    "required": ["file"],
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Report document"},
                        "501": {"description": "PDF backend missing"},
                    },
                }
            },
            "/api/v1/health": {
                "get": {
                    "tags": ["health"],
                    "summary": "Liveness probe (v1).",
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/api/v1/detectors": {
                "get": {
                    "tags": ["v1"],
                    "summary": "Detector catalog (type/region/compliance/severity).",
                    "responses": {"200": {"description": "Detector list"}},
                }
            },
            "/api/v1/scan": {
                "post": {
                    "tags": ["v1"],
                    "summary": "Submit a scan job (async, returns 202 + scan_id).",
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"},
                                        "mode": {"type": "string", "default": "mask"},
                                        "region": {"type": "string", "default": "ALL"},
                                        "preview": {
                                            "type": "string",
                                            "enum": ["masked", "raw"],
                                            "default": "masked",
                                        },
                                        "salt": {"type": "string"},
                                    },
                                    "required": ["file"],
                                }
                            }
                        }
                    },
                    "responses": {
                        "202": {"description": "ScanStatus JSON"},
                        "400": {"description": "Bad request"},
                    },
                }
            },
            "/api/v1/scan/{scan_id}/status": {
                "get": {
                    "tags": ["v1"],
                    "summary": "Poll a scan job.",
                    "parameters": [
                        {
                            "name": "scan_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "ScanStatus"},
                        "404": {"description": "Unknown scan_id"},
                    },
                }
            },
            "/api/v1/scan/{scan_id}/result": {
                "get": {
                    "tags": ["v1"],
                    "summary": "Fetch the finished risk report (masked preview).",
                    "parameters": [
                        {
                            "name": "scan_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Risk report"},
                        "404": {"description": "Unknown scan_id"},
                        "409": {"description": "Result not ready"},
                    },
                }
            },
            "/api/v1/clean": {
                "post": {
                    "tags": ["v1"],
                    "summary": "Sanitize a finished scan job (JSON summary).",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "scan_id": {"type": "string"},
                                        "mode": {"type": "string"},
                                        "region": {"type": "string"},
                                        "salt": {"type": "string"},
                                    },
                                    "required": ["scan_id"],
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Clean summary"},
                        "404": {"description": "Unknown scan_id"},
                        "409": {"description": "Scan not done"},
                    },
                }
            },
            "/api/v1/export/{scan_id}/file": {
                "get": {
                    "tags": ["v1"],
                    "summary": "Download the cleaned file bytes.",
                    "parameters": [
                        {
                            "name": "scan_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Cleaned file"},
                        "409": {"description": "No cleaned output"},
                    },
                }
            },
            "/api/v1/export/{scan_id}/report": {
                "get": {
                    "tags": ["v1"],
                    "summary": "Download the JSON risk report.",
                    "parameters": [
                        {
                            "name": "scan_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Report JSON"},
                        "409": {"description": "Result not ready"},
                    },
                }
            },
            "/api/openapi.json": {
                "get": {
                    "tags": ["health"],
                    "summary": "This OpenAPI document.",
                    "responses": {"200": {"description": "OpenAPI JSON"}},
                }
            },
        },
        "components": {"parameters": {"FileUpload": file_param}},
    }


DOCS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>NukePII API docs (swagger)</title>
<style>body{font-family:sans-serif;margin:32px}code{background:#f3f4f6;padding:2px 6px}</style>
</head><body><h1>NukePII API docs</h1>
<p>Swagger/OpenAPI contract: <a href="/api/openapi.json"><code>/api/openapi.json</code></a>.</p>
<p>Zero-trust note: the interactive swagger-ui bundle is intentionally NOT
auto-loaded from a third-party CDN. To browse interactively, serve your own
copy of swagger-ui and point it at <code>/api/openapi.json</code>.</p>
</body></html>
"""


__all__ = ["DOCS_HTML", "build_openapi"]
