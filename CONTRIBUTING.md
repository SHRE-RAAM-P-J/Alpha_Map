# Contributing to AlphaMap

Thanks for your interest in contributing! Here's everything you need to get started.

---

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/alphamap
cd alphamap
pip install -e ".[dev]"
```

The `[dev]` extra installs pytest, pytest-cov, and brotli so all tests run.

---

## Running tests

```bash
# All tests
pytest tests/ -v

# Single file
pytest tests/test_pipeline.py -v

# With coverage
pytest tests/ --cov=alphamap --cov-report=term-missing

# Quick smoke test
pytest tests/ -q --tb=short
```

All 145 tests must pass before opening a PR. The 3 brotli tests are skipped when brotli is not installed — that's expected.

---

## Project layout

```
alphamap/           Source package
tests/              pytest test suite (one file per subpackage)
MIGRATION.md        Step-by-step v1→v2 refactor guide
CHANGELOG.md        What changed and when
CONTRIBUTING.md     This file
pyproject.toml      Build config + dependencies
```

See README.md for the full package layout.

---

## Adding a new compression backend

1. Create `alphamap/backends/mybackend.py`:

```python
from .base import AbstractBackend, register_backend

@register_backend
class MyBackend(AbstractBackend):
    name = "mybackend"   # must be unique, lowercase

    def compress(self, data: bytes) -> bytes:
        ...

    def decompress(self, data: bytes) -> bytes:
        ...
```

2. Import it in `alphamap/backends/__init__.py`:

```python
from . import mybackend   # noqa: F401
```

3. Add tests in `tests/test_backends.py`.

4. If the backend requires an optional dependency, follow the brotli pattern:
   - Wrap the import in try/except
   - Add an optional extra in `pyproject.toml`
   - Mark tests with `@pytest.mark.skipif(not _AVAILABLE, reason="...")`

---

## Adding a strategy rule

Rules are scoring functions that bias backend selection. Add yours in `alphamap/strategy/selector.py` or register dynamically:

```python
from alphamap.strategy.selector import register_rule
from alphamap.core.types import FileProfile

@register_rule(weight=1.5)
def my_rule(profile: FileProfile, backend: str) -> float:
    # Return 0.0–1.0; higher = prefer this backend
    if backend == "mybackend" and profile.entropy < 4.0:
        return 0.85
    return 0.5
```

---

## Commit style

```
feat: add zstd backend
fix: PBKDF2 hash module bug on Windows
refactor: split stream.py into pipeline/ + formats/
test: add roundtrip tests for binary files
docs: update README with benchmark example
```

---

## Pull request checklist

- [ ] All existing tests pass (`pytest tests/ -q`)
- [ ] New code has tests
- [ ] Docstrings updated
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] No new dependencies without a corresponding `pyproject.toml` entry

---

## Reporting bugs

Open a GitHub issue with:
- AlphaMap version (`pip show alphamap`)
- Python version (`python --version`)
- OS
- Minimal reproducer (file type, command, error output)
