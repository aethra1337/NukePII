# nukepii-native — Rust hot-path (maturin / PyO3)

Sıcak yol checksum'ları + Aho-Corasick prefilter: `src/lib.rs`.

## İçerik

| Rust fonksiyon | Python karşılığı | Not |
|---|---|---|
| `luhn_valid` | `is_valid_luhn` | `\D` strip dahil, semantik birebir |
| `tr_national_id_valid` | `is_valid_tr_national_id` | Mod10/11, birebir |
| `verhoeff_valid` | `is_valid_aadhaar` çekirdeği | digits-only kernel |
| `iban_mod97` | `_iban_mod97` | remainder; uzunluk/ülke kontrolü Python'da kalır |
| `prefilter_scan`, `should_full_scan` | — | Aho-Corasick literal gate |
| `luhn_batch`, `tr_id_batch`, `verhoeff_batch`, `iban_batch`, `prefilter_batch` | — | rayon + `py.allow_threads` (GIL-free) |

`detectors.py` native'i **opsiyonel** kullanır (`_bridge.mod()` guarded import):
native yoksa veya hata verirse saf Python çalışır. Davranış kontratı değişmez.

## Derleme (CI / VS makinesi)

> Bu makinede Smart App Control + VS Build Tools yokluğu nedeniyle **yerel
> derleme yapılmaz**. `cargo check/build`, imzasız exe ürettiği için Defender/
> SAC'i tetikler — lokalde çalıştırmayın. Derleme GitHub Actions'ta olur.

```bash
# Windows (VS Build Tools olan makinede) veya CI'da:
pip install maturin
cd rust
maturin build --release --out ../dist
# Wheel'i KURMAYIN (nukepii-native dist'i, setuptools `nukepii` dist'i ile
# aynı top-level paketi paylaşır). Bunun yerine:
python -c "import zipfile,glob; z=zipfile.ZipFile(glob.glob('../dist/*.whl')[0]); z.extract('nukepii/_native.pyd','../nukepii_tmp');"
copy ..\nukepii_tmp\nukepii\_native.pyd ..\nukepii\_native.pyd
python -c "from nukepii.core.streamer import capabilities; print(capabilities())"
# -> {..., 'native': True, ...}
python -m pytest tests/test_native.py -q
```

Linux/macOS'ta `maturin develop --release` (venv aktif) doğrudan kurar.

## Performans hedefi

- Tekil checksum: 5-15x (LLVM auto-vec, alloc-free).
- Batch: `rayon` çekirdek başına ölçeklenir; `eval/benchmark.py --native` ile ölçülür.
- Prefilter: checksum gerektirmeyen chunk'larda regex katmanı atlanır.
