"""Tests for alphamap.core (constants, errors, types)."""

import pytest
from alphamap.core.constants import (
    MAGIC, FORMAT_VERSION, SALT_SIZE, NONCE_SIZE, TAG_SIZE,
    FLAG_EMBEDDED_DICT, FLAG_ZLIB_FALLBACK, FLAG_ENCRYPTED,
    DEFAULT_DICT_LIMIT, HIGH_ENTROPY_THRESHOLD,
)
from alphamap.core.errors import (
    AlphaMapError, BadMagicError, DecryptionError, CorruptionError,
    DictionaryError, CompressionError, NoStrategyError,
)
from alphamap.core.types import (
    CompressionMethod, FileType, FileProfile, CompressedPayload, BenchmarkResult,
)


def test_magic_bytes():
    assert MAGIC == b"AMAP"
    assert len(MAGIC) == 4


def test_sizes():
    assert SALT_SIZE == 16
    assert NONCE_SIZE == 12
    assert TAG_SIZE == 16


def test_flags_are_distinct_bits():
    assert FLAG_EMBEDDED_DICT & FLAG_ZLIB_FALLBACK == 0
    assert FLAG_EMBEDDED_DICT & FLAG_ENCRYPTED == 0
    assert FLAG_ZLIB_FALLBACK & FLAG_ENCRYPTED == 0


def test_error_hierarchy():
    for cls in [BadMagicError, DecryptionError, CorruptionError,
                DictionaryError, CompressionError, NoStrategyError]:
        assert issubclass(cls, AlphaMapError)
        assert issubclass(cls, Exception)


def test_compression_method_values():
    assert CompressionMethod.ALPHAMAP == 0
    assert CompressionMethod.ZLIB == 1
    assert CompressionMethod.STORED == 4


def test_file_profile_defaults():
    p = FileProfile()
    assert p.entropy == 0.0
    assert p.file_type == FileType.UNKNOWN
    assert p.is_utf8 is False


def test_compressed_payload_ratio():
    cp = CompressedPayload(
        data=b"x" * 50,
        method=CompressionMethod.ZLIB,
        original_size=100,
        compressed_size=50,
    )
    assert cp.ratio == 2.0


def test_benchmark_result_metrics():
    r = BenchmarkResult(
        label="test",
        original_size=1000,
        compressed_size=400,
        compress_time_ms=10.0,
        decompress_time_ms=5.0,
    )
    assert r.ratio == pytest.approx(2.5)
    assert r.space_saving_pct == pytest.approx(60.0)
