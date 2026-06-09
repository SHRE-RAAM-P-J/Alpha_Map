# AlphaMap

**Adaptive hybrid compression engine with AES-256-GCM authenticated encryption.**

AlphaMap v2 automatically analyses your file (entropy, type, structure) and picks the best compression backend — its own dictionary-based token encoder, zlib, gzip, lzma, or brotli. The result is optionally encrypted with AES-256-GCM using a PBKDF2-derived key so only the password holder can read it.

```
pip install alphamap
```

---

## Features

- **Automatic strategy selection** — Shannon entropy + file-type detection chooses the best backend per file
- **AlphaMap semantic compression** — bit-packed dictionary encoding optimised for natural-language text
- **Multiple backends** — zlib, gzip, lzma built-in; brotli optional (`pip install alphamap[brotli]`)
- **AES-256-GCM encryption** — authenticated, with PBKDF2 (200 000 rounds) key derivation
- **Backward compatible** — reads v1 `.am11` files; v1 Python API still works unchanged
- **Zero C dependencies** — pure Python + pycryptodome; no libmagic, no libz header needed
- **Benchmark mode** — compare all backends on your own data in one command

---

## Install

```bash
# Core (zlib, gzip, lzma, alphamap backends)
pip install alphamap

# With brotli backend
pip install alphamap[brotli]

# Dev / testing
pip install alphamap[dev]
```

Requires Python ≥ 3.10.

---

## CLI quick start

```bash
# Compress (auto-selects best backend)
alphamap compress notes.txt -k "my-password"
# → notes.txt.amap

# Compress with explicit output path
alphamap compress notes.txt notes.amap -k "my-password"

# Decompress
alphamap decompress notes.amap -k "my-password"
# → notes.txt

# No encryption (omit -k)
alphamap compress data.json

# Analyse a file — shows entropy, type, recommended backend
alphamap analyze data.json

# Inspect an archive without decompressing
alphamap inspect notes.amap

# Train a reusable dictionary from a large corpus
alphamap train corpus.txt mydict.json

# Compress using an external dictionary (smaller archive, no embedded dict)
alphamap compress notes.txt -k "pw" --no-embed-dict -d mydict.json

# Benchmark all backends on your file
alphamap benchmark corpus.txt

# Force a specific backend
alphamap compress notes.txt --strategy lzma
```

### `alphamap analyze` output example

```
File type       : text
MIME hint       : text/plain
Sample size     : 8,192 bytes
UTF-8           : yes
Entropy         : 4.231 bits/byte  [moderate]
Repetition score: 0.0842
Semantic score  : 0.6123

Recommended backend order: alphamap → zlib → gzip → lzma
```

### `alphamap benchmark` output example

```
Benchmark — corpus.txt
-------------------------------------------------------------------------------------------
Backend       Orig (B)    Comp (B)   Ratio   Saving    Compress   Decompress    Mem (KB)
-------------------------------------------------------------------------------------------
alphamap        48,210      11,340    4.25x    76.5%      12.3ms        8.1ms         312
lzma            48,210      13,891    3.47x    71.2%     210.4ms       18.3ms         980
zlib            48,210      16,022    3.01x    66.8%       3.2ms        1.4ms         128
gzip            48,210      16,034    3.01x    66.7%       3.4ms        1.5ms         130
-------------------------------------------------------------------------------------------
```

---

## Python API

### High-level — `Pipeline`

```python
from alphamap import Pipeline

# Compress with encryption
p = Pipeline(password="my-secret")
stats = p.compress("notes.txt", "notes.amap")
print(stats)
# {'original_size': 4821, 'compressed_size': 1134, 'final_size': 1289,
#  'ratio': 4.25, 'method': 'alphamap', 'backend': 'SemanticBackend'}

# Decompress
p.decompress("notes.amap", "notes_recovered.txt")

# Inspect without decompressing
meta = p.inspect("notes.amap")
# {'version': 2, 'method': 'ALPHAMAP', 'original_size': 4821,
#  'encrypted': True, 'embedded_dict': True, 'filename': 'notes.txt', ...}
```

### v1-compatible — `AlphaMapStream`

Existing v1 code works unchanged:

```python
from alphamap import AlphaMapStream

stream = AlphaMapStream("my-password")
stream.encrypt("notes.txt", "notes.am11")   # v1 extension still works
stream.decrypt("notes.am11", "notes_recovered.txt")
```

### Low-level — backends, analysis, strategy

```python
from alphamap.analysis.profiler import profile_file
from alphamap.strategy.selector import select_backends
from alphamap.backends import list_backends, get_backend

# Profile a file
profile = profile_file("corpus.txt")
print(profile.entropy, profile.file_type, profile.semantic_score)

# Ask the strategy selector which backend to use
ranked = select_backends(profile, list_backends())
print(ranked)  # ['alphamap', 'zlib', 'gzip', 'lzma']

# Use a backend directly
backend = get_backend("zlib")
compressed = backend.compress(b"hello world " * 1000)
recovered  = backend.decompress(compressed)
```

### Dictionary training and reuse

```python
from alphamap import AlphaMap

am = AlphaMap(dict_limit=4096)
am.train(open("large_corpus.txt").read())
am.save("mydict.json")

# Later — reuse the dictionary (no re-training needed)
p = Pipeline(password="pw")
p.compress("doc.txt", "doc.amap", embed_dict=False, dict_path="mydict.json")
p.decompress("doc.amap", "doc_recovered.txt", dict_path="mydict.json")
```

### Adding a custom backend

```python
from alphamap.backends.base import AbstractBackend, register_backend
import zstd  # hypothetical

@register_backend
class ZstdBackend(AbstractBackend):
    name = "zstd"

    def compress(self, data: bytes) -> bytes:
        return zstd.compress(data, level=19)

    def decompress(self, data: bytes) -> bytes:
        return zstd.decompress(data)

# Now it's automatically available to Pipeline and the strategy selector
```

### Adding a custom strategy rule

```python
from alphamap.strategy.selector import register_rule
from alphamap.core.types import FileProfile

@register_rule(weight=2.0)
def prefer_zstd_for_logs(profile: FileProfile, backend: str) -> float:
    if backend == "zstd" and profile.mime_type == "text/plain" and profile.entropy < 4.0:
        return 0.95
    return 0.5
```

---

## File format (.amap v2)

```
┌─────────────────────────────────────────────────────────┐
│  MAGIC       4 bytes   b"AMAP"                          │
│  VERSION     1 byte    uint8  (2 for v2)                │
│  FLAGS       2 bytes   uint16 bitmask                   │
│  SALT        16 bytes  PBKDF2 salt (zeros if no crypto) │
│  NONCE       12 bytes  AES-GCM nonce (zeros if no crypto│
│  HEADER_LEN  4 bytes   uint32 byte length of blob       │
│  HEADER_BLOB variable  UTF-8 JSON metadata              │
│  PAYLOAD     variable  compressed (+ encrypted) data    │
│  TAG         16 bytes  AES-GCM tag (zeros if no crypto) │
└─────────────────────────────────────────────────────────┘
```

**FLAGS bitmask:**

| Bit | Constant            | Meaning                            |
|-----|---------------------|------------------------------------|
| 0   | `FLAG_EMBEDDED_DICT`| Dictionary embedded in header blob |
| 1   | `FLAG_ZLIB_FALLBACK`| Payload is zlib (not AlphaMap)     |
| 2   | `FLAG_ENCRYPTED`    | Payload is AES-GCM encrypted       |
| 3   | `FLAG_BROTLI`       | Reserved for v0.3                  |
| 4   | `FLAG_LZMA`         | Reserved for v0.3                  |

AlphaMap v2 reads v1 `.am11` files transparently.

---

## How AlphaMap semantic compression works

1. **Tokenise** — split text into word and whitespace tokens (lossless: `''.join(tokenize(t)) == t`)
2. **Train dictionary** — frequency-sort tokens; whitespace gets a 10× boost so it costs fewer bits
3. **Bit-pack** — encode each token as a ~13-bit ID + 2-bit case flag; OOV words stored verbatim
4. **Fallback** — compare against zlib level 9; keep whichever is smaller
5. **Encrypt** (optional) — AES-256-GCM; key derived via PBKDF2-HMAC-SHA256, 200 000 iterations

---

## Package layout

```
alphamap/
├── __init__.py          Public API + v1 compat shims
├── core/
│   ├── constants.py     Protocol constants (magic, flags, sizes)
│   ├── errors.py        Exception hierarchy
│   └── types.py         Dataclasses (FileProfile, CompressedPayload, …)
├── analysis/
│   ├── entropy.py       Shannon entropy + repetition score
│   ├── detector.py      File type detection (magic bytes + heuristics)
│   └── profiler.py      Combines detection + entropy → FileProfile
├── strategy/
│   └── selector.py      Rule-based backend scoring + selection
├── backends/
│   ├── base.py          AbstractBackend + registry
│   ├── zlib_backend.py
│   ├── gzip_backend.py
│   ├── lzma_backend.py
│   ├── brotli_backend.py (optional)
│   └── semantic_backend.py
├── semantic/
│   ├── bitpacking.py    BitWriter / BitReader
│   └── dictionary.py   AlphaMap dictionary encoder
├── crypto/
│   ├── kdf.py           PBKDF2-HMAC-SHA256 key derivation
│   └── integrity.py     CRC32 helpers
├── formats/
│   └── header.py        .amap header read / write
├── pipeline/
│   └── engine.py        Pipeline — top-level compress / decompress
├── benchmark/
│   └── runner.py        Multi-backend benchmarking
└── cli/
    └── main.py          Click CLI (compress, decompress, analyze, …)
```

---

## Development

```bash
git clone https://github.com/YOUR_USERNAME/alphamap
cd alphamap
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=alphamap --cov-report=term-missing
```

See [MIGRATION.md](MIGRATION.md) for the step-by-step v1 → v2 refactor guide.

---

## Changelog

### v0.2.0 (current)
- **New**: `Pipeline` replaces `AlphaMapStream` as the primary interface
- **New**: Automatic strategy selection based on Shannon entropy + file type
- **New**: `analysis` subpackage — entropy, type detection, file profiler
- **New**: `strategy` subpackage — rule-based backend scoring (extensible)
- **New**: `backends` subpackage — plugin registry (`AbstractBackend`)
- **New**: gzip, lzma, brotli backends added alongside zlib
- **New**: `alphamap analyze`, `alphamap inspect`, `alphamap benchmark` CLI commands
- **New**: `.amap` v2 container format with JSON metadata header
- **New**: `Pipeline.inspect()` — read header metadata without decompressing
- **Compat**: All v1 `AlphaMapStream` / `CompressionEngine` call-sites still work
- **Compat**: v1 `.am11` files are readable by v2

### v0.1.0
- Initial release: AlphaMap semantic compression + AES-256-GCM encryption

---

## License

MIT © 2026 SHRE RAAM P J.
