# Changelog

All notable changes to AlphaMap are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.2.0] — 2026-05-23

### Added
- `Pipeline` class — new primary interface replacing `AlphaMapStream`
- `analysis` subpackage: Shannon entropy (`entropy.py`), file-type detection (`detector.py`), file profiler (`profiler.py`)
- `strategy` subpackage: rule-based backend scoring with `select_backends()` and `register_rule()` decorator for extensibility
- `backends` subpackage: `AbstractBackend` ABC + global registry (`register_backend`, `get_backend`, `list_backends`)
- New backends: `GzipBackend`, `LzmaBackend`, `BrotliBackend` (optional, install with `pip install alphamap[brotli]`)
- `benchmark` subpackage: `run_benchmark()` and `print_report()` for multi-backend comparison
- `formats` subpackage: `.amap` v2 container header (read + write), JSON metadata blob
- `Pipeline.inspect()`: read header metadata without decompressing
- New CLI commands: `alphamap analyze`, `alphamap inspect`, `alphamap benchmark`
- `--strategy` flag on `alphamap compress` to force a specific backend
- `--json-output` flag on `analyze`, `inspect`, `benchmark` for machine-readable output
- `core/errors.py`: typed exception hierarchy (`AlphaMapError`, `DecryptionError`, `CorruptionError`, …)
- `core/types.py`: dataclasses `FileProfile`, `CompressedPayload`, `BenchmarkResult`, `CompressionMethod` enum
- `core/constants.py`: single source of truth for all protocol constants
- 145-test suite across 9 test files; brotli tests skip cleanly when not installed

### Changed
- `.amap` v2 format: fixed 39-byte prefix + variable JSON header blob (richer metadata: filename, timestamp, CRC32, method)
- `Pipeline` returns a stats dict from `compress()` (no more side-effect prints — callers decide what to display)
- PBKDF2 now uses `Crypto.Hash.SHA256` module object (fixes `AttributeError` on some pycryptodome builds)
- pyproject.toml: `requires-python = ">=3.10"` (uses `match`, walrus, `str.removesuffix`)
- CLI entry point updated: `alphamap.cli.main:main` (was `alphamap.cli:main`)
- Old `encrypt` / `decrypt` subcommands renamed to `compress` / `decompress`

### Fixed
- PBKDF2 hash module bug present in v0.1.0 (passed raw `hashlib.sha256` instead of pycryptodome SHA256 module)
- `setuptools.backends.legacy:build` → `setuptools.build_meta` (fixes build on older setuptools)

### Backward compatible
- `AlphaMapStream("password").encrypt(src, dst)` / `.decrypt(src, dst)` — unchanged, delegates to `Pipeline`
- `CompressionEngine(alphamap).compress(text)` / `.decompress(data, flags)` — unchanged
- `from alphamap import AlphaMap, AlphaMapStream, CompressionEngine` — all still importable from top level
- `.am11` v1 files are readable by v2 `Pipeline.decompress()`

---

## [0.1.0] — 2026-05-22

### Added
- AlphaMap semantic compression: frequency-sorted dictionary + bit-packed token encoding
- AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation (200 000 rounds)
- zlib fallback: automatically uses zlib when it produces smaller output than AlphaMap
- Embedded dictionary support: dictionary serialised into the encrypted container
- External dictionary support: `--dict` flag for shared dictionaries across files
- `AlphaMapStream` high-level API: `encrypt()` / `decrypt()`
- `AlphaMap` dictionary class: `train()`, `save()`, `load()`, `encode_tokens()`, `decode_tokens()`
- `BitWriter` / `BitReader`: MSB-first bit-level I/O
- CLI: `alphamap encrypt`, `alphamap decrypt`, `alphamap train`
- CRC32 integrity check inside the authenticated envelope
- `.am11` v1 container format
- 6-test suite covering tokenize, encode/decode, compress, encrypt/decrypt roundtrips
