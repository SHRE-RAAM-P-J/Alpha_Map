"""
Strategy selector: maps a FileProfile to an ordered list of backend names.

Design:
    - Each rule is a pure function (FileProfile) → float score [0.0, 1.0].
    - The selector aggregates all rules for each backend and picks the winner.
    - Adding a new rule or backend requires zero changes to this file —
      just call register_rule() or backends.register_backend().
    - No ML, no lookup tables that require maintenance — pure heuristics
      derived from real entropy / type signals.

The selector returns a list so the pipeline can fall through to the next
backend if the first one fails (e.g. brotli not installed).
"""

from __future__ import annotations

from typing import Callable, List

from ..core.types import FileProfile, FileType
from ..core.constants import HIGH_ENTROPY_THRESHOLD, LOW_ENTROPY_THRESHOLD
from ..core.errors import NoStrategyError


# Type alias for a rule function
Rule = Callable[[FileProfile, str], float]

# Module-level rule registry: (rule_fn, weight)
_RULES: List[tuple[Rule, float]] = []


def register_rule(weight: float = 1.0):
    """Decorator — register a scoring rule with optional *weight*.

    A rule is a function (profile: FileProfile, backend_name: str) → float
    returning a score in [0.0, 1.0] where 1.0 means "strongly prefer this
    backend" and 0.0 means "this backend is a bad fit".
    """
    def decorator(fn: Rule) -> Rule:
        _RULES.append((fn, weight))
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Built-in scoring rules
# ---------------------------------------------------------------------------

@register_rule(weight=3.0)
def _already_compressed(profile: FileProfile, backend: str) -> float:
    """Strongly disfavour all compression when entropy is very high."""
    if profile.entropy >= HIGH_ENTROPY_THRESHOLD:
        return 0.0 if backend != "stored" else 1.0
    return 0.5  # neutral — let other rules decide


@register_rule(weight=2.0)
def _semantic_for_text(profile: FileProfile, backend: str) -> float:
    """Favour semantic backend for natural-language text."""
    if backend != "alphamap":
        return 0.5
    if profile.file_type == FileType.TEXT and profile.semantic_score > 0.5:
        return 0.9
    if profile.file_type in (FileType.TEXT, FileType.SOURCE) and profile.is_utf8:
        return 0.6
    return 0.2


@register_rule(weight=2.0)
def _brotli_for_structured_text(profile: FileProfile, backend: str) -> float:
    """Brotli is excellent for JSON, CSV, HTML, and source code."""
    if backend != "brotli":
        return 0.5
    if profile.file_type in (FileType.JSON, FileType.CSV, FileType.SOURCE):
        return 0.85
    if profile.file_type == FileType.TEXT and profile.entropy < 5.5:
        return 0.65
    return 0.3


@register_rule(weight=1.5)
def _lzma_for_binary(profile: FileProfile, backend: str) -> float:
    """lzma has the best ratio for binary data that is not already compressed."""
    if backend != "lzma":
        return 0.5
    if profile.file_type == FileType.BINARY and profile.entropy < HIGH_ENTROPY_THRESHOLD:
        return 0.8
    return 0.3


@register_rule(weight=1.0)
def _zlib_universal_fallback(profile: FileProfile, backend: str) -> float:
    """zlib is always a reasonable fallback — available everywhere, fast."""
    if backend != "zlib":
        return 0.5
    return 0.4   # baseline — other backends should beat this on good inputs


@register_rule(weight=1.0)
def _entropy_penalty(profile: FileProfile, backend: str) -> float:
    """Generic entropy-based penalty: higher entropy → lower score for all backends."""
    if backend == "stored":
        return 0.5
    normalised = profile.entropy / 8.0   # 0.0 (best) → 1.0 (worst)
    return max(0.0, 1.0 - normalised)


# ---------------------------------------------------------------------------
# Selector
# ---------------------------------------------------------------------------

# Preferred evaluation order (used as tiebreaker and fallback sequence)
_PREFERRED_ORDER = ["alphamap", "brotli", "zlib", "gzip", "lzma", "stored"]


def select_backends(profile: FileProfile, available: List[str]) -> List[str]:
    """Return *available* backends sorted best-first for the given *profile*.

    Args:
        profile:   Result of ``analysis.profiler.profile_file()``.
        available: Names of backends currently registered (from
                   ``backends.list_backends()``).

    Returns:
        Ordered list of backend names.  The pipeline should try them in
        order and use the first one that succeeds.

    Raises:
        :class:`~alphamap.core.errors.NoStrategyError` if *available* is empty.
    """
    if not available:
        raise NoStrategyError("No compression backends are registered")

    scores: dict[str, float] = {}
    for backend in available:
        total_weight = 0.0
        weighted_score = 0.0
        for rule, weight in _RULES:
            weighted_score += rule(profile, backend) * weight
            total_weight += weight
        scores[backend] = weighted_score / total_weight if total_weight else 0.0

    # Sort: highest score first, tiebreak by preferred order
    def sort_key(name: str):
        pos = _PREFERRED_ORDER.index(name) if name in _PREFERRED_ORDER else 99
        return (-scores[name], pos)

    return sorted(available, key=sort_key)


def best_backend(profile: FileProfile, available: List[str]) -> str:
    """Return the single best backend name for *profile*.

    Convenience wrapper around :func:`select_backends`.
    """
    return select_backends(profile, available)[0]
