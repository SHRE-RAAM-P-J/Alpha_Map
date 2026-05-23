"""Tests for alphamap.backends — registry, ABC, and each concrete backend."""

import pytest
import alphamap.backends  # ensures all backends register themselves

from alphamap.backends.base import (
    AbstractBackend, register_backend, get_backend, list_backends,
)
from alphamap.backends.zlib_backend import ZlibBackend
from alphamap.backends.gzip_backend import GzipBackend
from alphamap.backends.lzma_backend import LzmaBackend
from alphamap.backends.semantic_backend import SemanticBackend
from alphamap.core.errors import DictionaryError


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_all_backends_registered():
    registered = list_backends()
    assert "alphamap" in registered
    assert "zlib" in registered
    assert "gzip" in registered
    assert "lzma" in registered


def test_get_backend_returns_correct_type():
    assert isinstance(get_backend("zlib"), ZlibBackend)
    assert isinstance(get_backend("alphamap"), SemanticBackend)


def test_get_backend_unknown_raises():
    with pytest.raises(KeyError, match="no_such_backend"):
        get_backend("no_such_backend")


def test_register_backend_requires_name():
    with pytest.raises(ValueError, match="non-empty"):
        @register_backend
        class _Bad(AbstractBackend):
            name = ""
            def compress(self, d): return d
            def decompress(self, d): return d


def test_list_backends_is_sorted():
    names = list_backends()
    assert names == sorted(names)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEXT_DATA = (
    b"the quick brown fox jumps over the lazy dog "
    b"the fox was quick and the dog was lazy "
) * 50

BINARY_DATA = bytes(i % 256 for i in range(4096))


def roundtrip(backend: AbstractBackend, data: bytes) -> None:
    compressed = backend.compress(data)
    recovered = backend.decompress(compressed)
    assert recovered == data, f"{backend.name}: round-trip failed"


def assert_smaller(backend: AbstractBackend, data: bytes) -> None:
    compressed = backend.compress(data)
    assert len(compressed) < len(data), (
        f"{backend.name}: {len(compressed)} >= {len(data)} — no compression"
    )


# ---------------------------------------------------------------------------
# ZlibBackend
# ---------------------------------------------------------------------------

class TestZlibBackend:
    def test_roundtrip_text(self):
        roundtrip(ZlibBackend(), TEXT_DATA)

    def test_roundtrip_binary(self):
        roundtrip(ZlibBackend(), BINARY_DATA)

    def test_compresses_text(self):
        assert_smaller(ZlibBackend(), TEXT_DATA)

    def test_name(self):
        assert ZlibBackend.name == "zlib"

    def test_empty(self):
        roundtrip(ZlibBackend(), b"")


# ---------------------------------------------------------------------------
# GzipBackend
# ---------------------------------------------------------------------------

class TestGzipBackend:
    def test_roundtrip_text(self):
        roundtrip(GzipBackend(), TEXT_DATA)

    def test_compresses_text(self):
        assert_smaller(GzipBackend(), TEXT_DATA)

    def test_name(self):
        assert GzipBackend.name == "gzip"


# ---------------------------------------------------------------------------
# LzmaBackend
# ---------------------------------------------------------------------------

class TestLzmaBackend:
    def test_roundtrip_text(self):
        roundtrip(LzmaBackend(), TEXT_DATA)

    def test_roundtrip_binary(self):
        roundtrip(LzmaBackend(), BINARY_DATA)

    def test_compresses_text(self):
        assert_smaller(LzmaBackend(), TEXT_DATA)

    def test_name(self):
        assert LzmaBackend.name == "lzma"


# ---------------------------------------------------------------------------
# BrotliBackend (optional)
# ---------------------------------------------------------------------------

try:
    from alphamap.backends.brotli_backend import BrotliBackend as _BB
    _BROTLI = True
except ImportError:
    _BROTLI = False


@pytest.mark.skipif(not _BROTLI, reason="brotli not installed")
class TestBrotliBackend:
    def test_roundtrip_text(self):
        from alphamap.backends.brotli_backend import BrotliBackend
        roundtrip(BrotliBackend(), TEXT_DATA)

    def test_compresses_text(self):
        from alphamap.backends.brotli_backend import BrotliBackend
        assert_smaller(BrotliBackend(), TEXT_DATA)

    def test_name(self):
        from alphamap.backends.brotli_backend import BrotliBackend
        assert BrotliBackend.name == "brotli"


# ---------------------------------------------------------------------------
# SemanticBackend
# ---------------------------------------------------------------------------

class TestSemanticBackend:
    def test_roundtrip(self):
        backend = SemanticBackend()
        recovered = backend.decompress(backend.compress(TEXT_DATA))
        assert recovered == TEXT_DATA

    def test_compresses_text(self):
        assert_smaller(SemanticBackend(), TEXT_DATA)

    def test_name(self):
        assert SemanticBackend.name == "alphamap"

    def test_requires_utf8(self):
        from alphamap.core.errors import CompressionError
        backend = SemanticBackend()
        with pytest.raises(CompressionError):
            backend.compress(b"\x80\x81\x82\x83")

    def test_decompress_without_dict_raises(self):
        backend = SemanticBackend()
        with pytest.raises(DictionaryError):
            # Fresh instance has no dictionary
            backend.decompress(b"\x05\x00\x00\x00" + b"\x00" * 10)

    def test_set_word_map_roundtrip(self):
        b1 = SemanticBackend()
        compressed = b1.compress(TEXT_DATA)

        b2 = SemanticBackend()
        b2.set_word_map(b1.word_to_id, b1.dict_limit)
        recovered = b2.decompress(compressed)
        assert recovered == TEXT_DATA

    def test_save_and_load_dictionary(self, tmp_path):
        b1 = SemanticBackend()
        b1.compress(TEXT_DATA)
        path = str(tmp_path / "dict.json")
        b1.save_dictionary(path)

        b2 = SemanticBackend()
        b2.load_dictionary(path)
        recovered = b2.decompress(b1.compress(TEXT_DATA))
        assert recovered == TEXT_DATA

    def test_train_then_compress(self):
        backend = SemanticBackend()
        text = "hello world " * 100
        backend.train(text)
        compressed = backend.compress(text.encode("utf-8"))
        recovered = backend.decompress(compressed)
        assert recovered == text.encode("utf-8")

    def test_word_to_id_populated_after_compress(self):
        backend = SemanticBackend()
        backend.compress(TEXT_DATA)
        assert len(backend.word_to_id) > 0
