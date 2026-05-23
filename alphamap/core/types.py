"""
Shared data-transfer objects (dataclasses) for AlphaMap v2.

These are plain data containers — no logic, no imports from other
AlphaMap subpackages — so they can be imported anywhere safely.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Method enum — which backend produced the payload
# ---------------------------------------------------------------------------

class CompressionMethod(enum.IntEnum):
    """Compression method stored in the .amap container header."""
    ALPHAMAP = 0    # semantic token encoding (default)
    ZLIB     = 1    # zlib fallback
    BROTLI   = 2    # reserved for v0.3
    LZMA     = 3    # reserved for v0.3
    STORED   = 4    # no compression (already-compressed input)


# ---------------------------------------------------------------------------
# File analysis result
# ---------------------------------------------------------------------------

class FileType(enum.Enum):
    TEXT       = "text"
    JSON       = "json"
    CSV        = "csv"
    SOURCE     = "source"       # source code
    BINARY     = "binary"
    COMPRESSED = "compressed"   # already gzip/zip/etc.
    UNKNOWN    = "unknown"


@dataclass
class FileProfile:
    """
    Result of running the file analyzer on a sample of the input.

    Produced by ``analysis.profiler`` and consumed by ``strategy.selector``.
    """
    file_type: FileType = FileType.UNKNOWN
    entropy: float = 0.0           # Shannon entropy in bits/byte
    repetition_score: float = 0.0  # 0.0 (all unique) → 1.0 (all same)
    semantic_score: float = 0.0    # 0.0 (binary) → 1.0 (natural language)
    sample_size: int = 0           # bytes actually inspected
    is_utf8: bool = False
    mime_type: str = ""            # best-guess MIME string


# ---------------------------------------------------------------------------
# Compression result
# ---------------------------------------------------------------------------

@dataclass
class CompressedPayload:
    """
    Output of any compression backend's ``compress()`` call.
    Consumed by ``formats.writer``.
    """
    data: bytes
    method: CompressionMethod
    original_size: int
    compressed_size: int

    @property
    def ratio(self) -> float:
        """Compression ratio: original / compressed.  >1 means we shrank."""
        if self.compressed_size == 0:
            return 0.0
        return self.original_size / self.compressed_size


# ---------------------------------------------------------------------------
# Benchmark result
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    """One row in a benchmark report."""
    label: str                          # e.g. "AlphaMap", "gzip", "brotli"
    original_size: int                  # bytes
    compressed_size: int                # bytes
    compress_time_ms: float
    decompress_time_ms: float
    peak_memory_kb: int = 0             # optional — populated if tracemalloc used

    @property
    def ratio(self) -> float:
        if self.compressed_size == 0:
            return 0.0
        return self.original_size / self.compressed_size

    @property
    def space_saving_pct(self) -> float:
        if self.original_size == 0:
            return 0.0
        return 100.0 * (1 - self.compressed_size / self.original_size)
