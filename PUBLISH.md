# Publishing AlphaMap to PyPI

Step-by-step guide to release `pip install alphamap`.

---

## One-time setup

### 1. Create accounts
- [pypi.org](https://pypi.org/account/register/) — production PyPI
- [test.pypi.org](https://test.pypi.org/account/register/) — staging (same login, separate account)

### 2. Create API tokens
On both PyPI and TestPyPI → Account Settings → API tokens → Add API token (scope: entire account).

Save them somewhere safe. You'll use them as the password when twine asks, with `__token__` as the username.

### 3. Install build tools
```bash
pip install build twine
```

---

## Before every release

### Update these files:
- `pyproject.toml` → bump `version = "0.x.y"`
- `alphamap/__init__.py` → bump `__version__ = "0.x.y"`
- `CHANGELOG.md` → move `[Unreleased]` items under the new version + date

### Run the full test suite:
```bash
pytest tests/ -v
```
All 145 tests must pass.

---

## Build

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build source dist + wheel
python -m build
```

This produces:
```
dist/
  alphamap-0.2.0.tar.gz
  alphamap-0.2.0-py3-none-any.whl
```

---

## Test on TestPyPI first

```bash
twine upload --repository testpypi dist/*
# Username: __token__
# Password: pypi-<your-testpypi-token>
```

Install from TestPyPI in a fresh venv and verify it works:
```bash
python -m venv /tmp/testenv && source /tmp/testenv/bin/activate
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ alphamap
alphamap --version
alphamap benchmark
deactivate
```

---

## Upload to real PyPI

```bash
twine upload dist/*
# Username: __token__
# Password: pypi-<your-real-pypi-token>
```

Verify:
```bash
pip install alphamap
alphamap --version
```

---

## GitHub release

```bash
git tag v0.2.0
git push origin v0.2.0
```

Then on GitHub → Releases → Draft a new release → pick the tag → paste the relevant CHANGELOG section.

---

## Checklist

- [ ] Version bumped in `pyproject.toml` and `__init__.py`
- [ ] CHANGELOG updated
- [ ] All tests pass
- [ ] TestPyPI upload succeeds
- [ ] TestPyPI install works end-to-end
- [ ] Real PyPI upload done
- [ ] Git tag pushed
- [ ] GitHub release drafted
