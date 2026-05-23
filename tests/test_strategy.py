"""Tests for alphamap.strategy — scoring rules and backend selection."""

import pytest
import alphamap.backends  # trigger backend registration

from alphamap.strategy.selector import select_backends, best_backend, register_rule
from alphamap.core.types import FileProfile, FileType
from alphamap.core.errors import NoStrategyError
from alphamap.core.constants import HIGH_ENTROPY_THRESHOLD


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_profile(**kwargs) -> FileProfile:
    defaults = dict(
        file_type=FileType.TEXT,
        entropy=3.5,
        repetition_score=0.2,
        semantic_score=0.7,
        sample_size=4096,
        is_utf8=True,
        mime_type="text/plain",
    )
    defaults.update(kwargs)
    return FileProfile(**defaults)


ALL_BACKENDS = ["alphamap", "zlib", "gzip", "lzma"]


# ---------------------------------------------------------------------------
# select_backends
# ---------------------------------------------------------------------------

def test_select_returns_all_available():
    profile = make_profile()
    result = select_backends(profile, ALL_BACKENDS)
    assert set(result) == set(ALL_BACKENDS)


def test_select_returns_sorted_list():
    profile = make_profile()
    result = select_backends(profile, ALL_BACKENDS)
    assert len(result) == len(ALL_BACKENDS)


def test_select_text_prefers_semantic():
    profile = make_profile(
        file_type=FileType.TEXT,
        entropy=3.0,
        semantic_score=0.85,
        is_utf8=True,
    )
    result = select_backends(profile, ALL_BACKENDS)
    assert result[0] == "alphamap"


def test_select_binary_avoids_semantic():
    profile = make_profile(
        file_type=FileType.BINARY,
        entropy=6.5,
        semantic_score=0.0,
        is_utf8=False,
    )
    result = select_backends(profile, ALL_BACKENDS)
    # lzma or zlib should beat alphamap for binary
    top = result[0]
    assert top in ("lzma", "zlib", "gzip")


def test_select_high_entropy_deprioritises_compression():
    """Very high entropy → all compression backends score low."""
    profile = make_profile(
        file_type=FileType.COMPRESSED,
        entropy=7.9,
        semantic_score=0.0,
    )
    # None of the backends should score well, but the call must not crash
    result = select_backends(profile, ALL_BACKENDS)
    assert len(result) == len(ALL_BACKENDS)


def test_select_json_prefers_brotli_if_available():
    profile = make_profile(
        file_type=FileType.JSON,
        entropy=4.5,
        semantic_score=0.2,
        is_utf8=True,
    )
    with_brotli = ALL_BACKENDS + ["brotli"]
    result = select_backends(profile, with_brotli)
    assert result[0] == "brotli"


def test_select_empty_backends_raises():
    with pytest.raises(NoStrategyError):
        select_backends(make_profile(), [])


def test_best_backend_returns_string():
    profile = make_profile()
    result = best_backend(profile, ALL_BACKENDS)
    assert isinstance(result, str)
    assert result in ALL_BACKENDS


def test_single_backend_always_selected():
    profile = make_profile()
    result = select_backends(profile, ["zlib"])
    assert result == ["zlib"]


# ---------------------------------------------------------------------------
# register_rule (extensibility)
# ---------------------------------------------------------------------------

def test_custom_rule_can_bias_selection():
    """A heavily weighted rule should override built-in heuristics."""
    from alphamap.strategy import selector as sel

    @sel.register_rule(weight=100.0)
    def _always_lzma(profile, backend):
        return 1.0 if backend == "lzma" else 0.0

    profile = make_profile(file_type=FileType.TEXT, entropy=2.0, semantic_score=0.95)
    result = select_backends(profile, ALL_BACKENDS)
    # Our rule dominates — lzma should now be first
    assert result[0] == "lzma"

    # Clean up: remove the rule so it doesn't affect other tests
    sel._RULES.pop()
