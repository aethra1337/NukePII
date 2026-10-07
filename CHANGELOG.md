# Changelog

## Unreleased — DevOps + DX bundle
- OpenAPI 3.1 (`nukepii/web/openapi.py`): `GET /api/openapi.json`, `GET /api/docs` (Swagger UI), `nukepii openapi --out openapi/openapi.json`, committed spec in `openapi/`.
- Stdlib-only SDK (`nukepii/client.py`): health/detectors/scan/wait/clean/export, `examples/sdk_example.py`.
- SARIF 2.1.0 export (`nukepii/core/sarif.py`): `nukepii scan --format sarif|json|table`.
- Bulk CI scanning: `nukepii scan-dir --dir --pattern --fail-on LEVEL`.
- DevOps: `Dockerfile` (non-root, healthcheck), `docker-compose.yml`, `.dockerignore`, `.pre-commit-config.yaml`, `Makefile`; CI gains OpenAPI contract check, SDK smoke, Docker build.
- Lint: fixed `eval/benchmark.py` findings, `RUF001` ignore for Turkish CLI help text.

## 0.4.0 — Rust Native Crate (maturin/PyO3, opt-in)
- `rust/` crate: Luhn / TR-ID Mod10-11 / Verhoeff / IBAN-Mod97 (Python
  semantiğiyle birebir, `\D` strip dahil) + Aho-Corasick prefilter +
  rayon GIL-free batch API (`*_batch`, `prefilter_batch`).
- `detectors.py` native'i guarded import ile kullanır; yoksa/hata verirse
  saf Python'a düşer (kontrat değişmez, recall %100 korunur).
- `core/_bridge.py` loader, `capabilities()["native"]`, `tests/test_native.py`
  (native yoksa skip), `.github/workflows/native.yml` CI wheel + parity.
- Not: SAC/Defender açık ve VS Build Tools'suz makinelerde yerel derleme
  yapılmaz; wheel CI'da üretilir, `.pyd` repo paketine kopyalanır
  (bkz. `rust/README.md`).

## 0.3.0 — Faz-1/2/3 Roadmap (Safe Preview, Rules, Vault/FPE, Parallel, Report)
- **Faz-1 Kritik:** Safe Preview default `masked` (`preview_mode`, `raw_exposed`,
  `NUKEPII_ALLOW_RAW=1` olmadan raw PII dönmez) — streamer + web + CLI;
  RFC4180 record-based CSV sanitize (gömülü newline fix); `eval/benchmark.py`
  (MB/s, rows/s, peak RSS, backend matrix); custom rules MVP
  (`core/rules.py`, `PIIDetector(custom_rules=, rules_dir=)`, `nukepii rules`);
  ETH EIP-55 (`is_valid_eth_eip55`, keccak varsa confidence 1.0).
- **Faz-2 Enterprise:** `core/extractors.py` (parquet/avro/xlsx/docx/pdf-text),
  `core/vault.py` (SQLite reversible tokenization, AESGCM varsa secure),
  `core/fpe.py` (format-preserving lite), `Sanitizer(mode=vault|fpe)`,
  `core/anonymize.py` (k-anonymity/l-diversity/t-closeness),
  `connectors/` (SQL sampling), `web/report.py` + `POST /api/report` (HTML/PDF audit).
- **Faz-3 İleri:** `DataStreamer(workers=N)` ThreadPool CSV paralel,
  `core/context.py` lexical guard, `core/ner_onnx.py` + `core/extractors_ocr.py`
  stub (optional), `core/_bridge.py` Rust/PyO3 iskelet, `capabilities()` genişledi
  (native/keccak/yaml/onnx/ocr/parquet), `tests/test_roadmap.py` + `test_fuzz.py`,
  `pyproject` extras (ocr/ner/report/formats/crypto/test).
- Kontrat korundu: accuracy recall %100, tüm eski testler + 11 yeni test yeşil.

## 0.2.0
- 42 → **80 detectors**: EU IDs (NL BSN, BE National Number, FI HETU, SE
  Personnummer, NO Fødselsnummer, PT NIF, RO CNP, GR AFM), finance
  (US ABA/ITIN, ISIN, SEDOL, IN IFSC, AU ABN), APAC/MEA IDs (CN, KR, SG,
  IL, ZA, TH, TW, HK, JP My Number), devices (IMEI context-gated, VIN),
  health (US DEA, Medicare MBI), crypto (BTC Base58Check/bech32, ETH),
  secrets (Telegram, Anthropic, Hugging Face, GitLab, npm, PyPI, Twilio,
  SendGrid, Discord webhook).
- 14 → **23 regions** (CN, KR, SG, IL, ZA, TH, TW, HK, JP added).
- FP fixes from the accuracy harness: TR phone no longer matches windows
  inside longer digit runs; IL scan requires 8-9 digits.
- `eval/accuracy.py`: synthetic corpus, per-type recall (100%) + noise FP probe.
- Quality gates: ruff config + GitHub Actions CI (lint, pytest, harness).

## 0.1.0
- Initial engine: 42 detectors, region filters + compliance tagging,
  mask/hash/pseudonymize/redact/noise sanitizers, chunk streaming
  (Polars/Pandas/stdlib), Typer CLI, Flask dashboard (TR/EN, dark/light).
