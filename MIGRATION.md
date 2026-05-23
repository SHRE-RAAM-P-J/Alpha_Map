# AlphaMap v1 → v2 Migration Guide

This document describes the exact steps to migrate an existing v1 AlphaMap
repository to the v2 modular architecture.  Every step produces a runnable,
testable state.  No step rewrites everything at once.

---

## Branch strategy

```
main
└── refactor/v2-architecture      ← all refactor work goes here
    ├── refactor/phase1-skeleton  ← folder structure only
    ├── refactor/phase2-core      ← core/ + crypto/
    ├── refactor/phase3-semantic  ← semantic/ backends/
    ├── refactor/phase4-pipeline  ← analysis/ strategy/ pipeline/
    └── refactor/phase5-cli       ← cli/ benchmark/ pyproject.toml
```

Merge each phase branch into `refactor/v2-architecture` before starting the
next.  When all phases pass CI, merge to `main` as a single squash commit.

---

## Phase 1 — Skeleton (no logic moves yet)

```bash
git checkout -b refactor/phase1-skeleton

# Create directories
mkdir -p alphamap/{core,analysis,strategy,semantic,backends,pipeline,crypto,formats,benchmark,cli}
touch alphamap/{core,analysis,strategy,semantic,backends,pipeline,crypto,formats,benchmark,cli}/__init__.py

# Copy this file structure into the repo root (see v2 layout)

git add alphamap/
git commit -m "refactor: add v2 package skeleton (empty modules)"
```

**All existing tests must still pass after this commit.**

---

## Phase 2 — Core + Crypto (pure leaf modules, no logic change)

Move files:
- `alphamap/crypto.py` → split into `alphamap/crypto/kdf.py` + `alphamap/crypto/integrity.py`
- Create `alphamap/core/constants.py`, `alphamap/core/errors.py`, `alphamap/core/types.py`

Add a shim in the old location:

```python
# alphamap/crypto.py  (KEEP during migration — delete in Phase 5)
from alphamap.crypto.kdf import derive_key          # noqa: F401
from alphamap.crypto.integrity import *             # noqa: F401, F403
```

```bash
git add alphamap/core/ alphamap/crypto/
git commit -m "refactor: extract core constants/errors/types; split crypto module"
```

Existing tests still pass because `alphamap.crypto` still exports everything.

---

## Phase 3 — Semantic + Backends

Move files:
- `alphamap/bitpacking.py` → `alphamap/semantic/bitpacking.py`
- `alphamap/dictionary.py` → `alphamap/semantic/dictionary.py`
  - Update imports: `from alphamap.bitpacking` → `from .bitpacking`

Add shims:

```python
# alphamap/bitpacking.py
from alphamap.semantic.bitpacking import BitWriter, BitReader  # noqa

# alphamap/dictionary.py
from alphamap.semantic.dictionary import AlphaMap, tokenize  # noqa
```

Create `alphamap/backends/` with the ABC and all concrete backends.

```bash
git add alphamap/semantic/ alphamap/backends/ alphamap/bitpacking.py alphamap/dictionary.py
git commit -m "refactor: move semantic modules; introduce AbstractBackend + backends/"
```

---

## Phase 4 — Analysis + Strategy + Pipeline

- Create `alphamap/analysis/` (entropy, detector, profiler)
- Create `alphamap/strategy/` (selector, rules)
- Migrate `alphamap/stream.py` logic into `alphamap/pipeline/engine.py`

Keep `alphamap/stream.py` as a shim:

```python
# alphamap/stream.py
from alphamap.pipeline.engine import Pipeline as AlphaMapStream  # noqa
```

The v1 `AlphaMapStream` constructor took only `password`.  The shim wraps
`Pipeline(password=password)` transparently.

```bash
git add alphamap/analysis/ alphamap/strategy/ alphamap/pipeline/ alphamap/stream.py
git commit -m "refactor: add analysis + strategy + pipeline; shim stream.py"
```

---

## Phase 5 — CLI + Benchmark + Cleanup

- Replace `alphamap/cli.py` with `alphamap/cli/main.py` (Click-based)
- Create `alphamap/benchmark/runner.py`
- Update `pyproject.toml` entry point: `alphamap.cli.main:main`
- Delete the old shim files (`bitpacking.py`, `dictionary.py`, `stream.py`, `crypto.py`)
- Update `alphamap/__init__.py` to re-export from v2 paths

```bash
git add alphamap/cli/ alphamap/benchmark/ pyproject.toml alphamap/__init__.py
git rm alphamap/bitpacking.py alphamap/dictionary.py alphamap/stream.py alphamap/crypto.py
git commit -m "refactor: v2 CLI + benchmark; remove v1 shims; update entry point"
```

---

## Backward compatibility guarantees

| v1 call-site                             | v2 status        |
|------------------------------------------|------------------|
| `from alphamap import AlphaMap`          | ✅ unchanged      |
| `from alphamap import AlphaMapStream`    | ✅ shim in place  |
| `from alphamap import CompressionEngine` | ✅ shim in place  |
| `from alphamap.bitpacking import ...`    | ✅ until Phase 5  |
| `from alphamap.dictionary import ...`    | ✅ until Phase 5  |
| `.am11` files (v1 format)               | ✅ readable by v2 |
| `alphamap compress` CLI command          | ✅ enhanced       |

---

## Testing strategy after each phase

```bash
# After every commit:
python -m pytest tests/ -x -q          # must be 0 failures

# After Phase 3 (backends):
python -m pytest tests/test_backends.py tests/test_semantic.py -v

# After Phase 4 (pipeline):
python -m pytest tests/test_pipeline.py -v  # all roundtrips pass

# Before merging to main:
python -m pytest tests/ --tb=short      # 145/145
```

---

## What NOT to migrate

- Do not port `phase4.py` — it's a monolith used for experimentation.
  Everything useful in it is already in `alphamap/` and now in v2.
- Do not add async I/O during migration — it breaks the contract without benefit.
- Do not change the `.amap` v2 format during migration — format changes get
  their own commit and increment `FORMAT_VERSION`.
