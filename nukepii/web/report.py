"""Audit report builder — Faz-2 (HTML always, PDF when WeasyPrint present).

scan_result (from DataStreamer.scan_file / scan_file_local) -> HTML string.
PDF: best-effort via WeasyPrint, else raise ImportError with hint.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any


def build_html(result: dict[str, Any]) -> str:
    f = html.escape
    rows = "".join(
        f"<tr><td>{f(str(b.get('type')))}</td><td>{int(b.get('count',0))}</td>"
        f"<td>{f(','.join(b.get('compliance',[])))}</td></tr>"
        for b in result.get("breakdown", []))
    heat = "".join(
        f"<tr><td>{f(str(h.get('label')))}</td><td>{int(h.get('count',0))}</td>"
        f"<td>{int(h.get('risk',0))}</td></tr>"
        for h in result.get("heatmap", {}).get("items", [])[:20])
    comp = result.get("compliance_summary", {})
    comp_s = ", ".join(f"{k}: {v}" for k, v in comp.items())
    prev = "".join(
        f"<tr><td>{int(p.get('line',0))}</td><td><code>{f(str(p.get('clean',''))[:200])}</code></td></tr>"
        for p in result.get("preview", [])[:8])
    now = datetime.now(UTC).isoformat()
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<title>NukePII Audit — {f(str(result.get('filename','')))}</title>
<style>body{{font-family:sans-serif;margin:32px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px 8px;font-size:13px}}th{{background:#f3f4f6}}</style>
</head><body>
<h1>NukePII Uyumluluk Raporu</h1>
<p>Dosya: <b>{f(str(result.get('filename','')))}</b> · {int(result.get('units',0))} {f(str(result.get('unit_kind','')))}
· Risk <b>{int(result.get('risk_score',0))}/100 {f(str(result.get('risk_label','')))}</b>
· Engine {f(str(result.get('engine','')))} · {f(now)}</p>
<p>Preview modu: {f(str(result.get('preview_mode','masked')))} (raw_exposed={result.get('raw_exposed',False)})</p>
<h2>Compliance özeti</h2><p>{f(comp_s)}</p>
<h2>PII dağılımı</h2><table><tr><th>Tip</th><th>Adet</th><th>Uyumluluk</th></tr>{rows}</table>
<h2>Isı haritası (ilk 20)</h2><table><tr><th>Alan</th><th>Vuruş</th><th>Risk</th></tr>{heat}</table>
<h2>Maskeli önizleme (ilk 8)</h2><table><tr><th>Satır</th><th>Temiz</th></tr>{prev}</table>
<p><small>Yöntem: regex + checksum (Luhn/Mod97/Verhoeff vb.), region={f(str(result.get('region','ALL')))}.
Ham PII bu raporda yer almaz (Safe Preview).</small></p>
</body></html>"""


def build_pdf(result: dict[str, Any]) -> bytes:
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:
        raise ImportError("weasyprint required for PDF (pip install weasyprint)") from exc
    return HTML(string=build_html(result)).write_pdf()


__all__ = ["build_html", "build_pdf"]
