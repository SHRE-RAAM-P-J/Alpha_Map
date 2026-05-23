"""Tests for alphamap.analysis — entropy, detection, and profiling."""

import json
import pytest

from alphamap.analysis.entropy import entropy, repetition_score
from alphamap.analysis.detector import detect_bytes_type, is_utf8
from alphamap.analysis.profiler import profile_bytes, profile_file
from alphamap.core.types import FileType
from alphamap.core.constants import HIGH_ENTROPY_THRESHOLD


# ---------------------------------------------------------------------------
# entropy
# ---------------------------------------------------------------------------

def test_entropy_empty():
    assert entropy(b"") == 0.0


def test_entropy_uniform():
    """All identical bytes → entropy = 0."""
    assert entropy(b"\x00" * 1000) == pytest.approx(0.0)


def test_entropy_two_values():
    """50/50 split of two values → entropy = 1.0 bit/byte."""
    data = bytes([0, 255] * 500)
    assert entropy(data) == pytest.approx(1.0, abs=1e-9)


def test_entropy_max():
    """256 distinct bytes each appearing exactly once → log2(256) = 8.0."""
    data = bytes(range(256))
    assert entropy(data) == pytest.approx(8.0, abs=1e-9)


def test_entropy_natural_text_range():
    text = b"the quick brown fox jumps over the lazy dog " * 20
    e = entropy(text)
    assert 3.0 < e < 6.0


def test_entropy_random_data_is_high():
    import os
    data = os.urandom(4096)
    assert entropy(data) > 7.0


# ---------------------------------------------------------------------------
# repetition_score
# ---------------------------------------------------------------------------

def test_repetition_score_all_same():
    assert repetition_score(b"\xAA" * 100) == pytest.approx(1.0)


def test_repetition_score_all_unique():
    # 256 distinct values → most common appears 1/256 times
    data = bytes(range(256))
    assert repetition_score(data) == pytest.approx(1 / 256)


def test_repetition_score_empty():
    assert repetition_score(b"") == 0.0


# ---------------------------------------------------------------------------
# detect_bytes_type
# ---------------------------------------------------------------------------

def test_detect_gzip_magic():
    assert detect_bytes_type(b"\x1f\x8b" + b"\x00" * 100) == FileType.COMPRESSED


def test_detect_zip_magic():
    assert detect_bytes_type(b"PK\x03\x04" + b"\x00" * 100) == FileType.COMPRESSED


def test_detect_amap_magic():
    assert detect_bytes_type(b"AMAP" + b"\x00" * 100) == FileType.COMPRESSED


def test_detect_json_object():
    data = json.dumps({"key": "value", "num": 42}).encode("utf-8")
    assert detect_bytes_type(data) == FileType.JSON


def test_detect_json_array():
    data = json.dumps([1, 2, 3]).encode("utf-8")
    assert detect_bytes_type(data) == FileType.JSON


def test_detect_csv():
    data = b"name,age,city\nAlice,30,Chennai\nBob,25,Mumbai\nCarol,35,Delhi\n"
    assert detect_bytes_type(data) == FileType.CSV


def test_detect_python_source():
    data = b"import os\ndef main():\n    return True\n"
    assert detect_bytes_type(data) == FileType.SOURCE


def test_detect_natural_text():
    data = (
        b"This is a sample of natural language text. "
        b"It contains many common English words arranged in sentences. "
        b"The quick brown fox jumps over the lazy dog. " * 5
    )
    assert detect_bytes_type(data) == FileType.TEXT


def test_detect_binary():
    data = bytes(range(256)) * 4
    # Not valid UTF-8, so must be BINARY
    result = detect_bytes_type(data)
    assert result in (FileType.BINARY, FileType.COMPRESSED)


def test_is_utf8_valid():
    assert is_utf8("hello world".encode("utf-8")) is True


def test_is_utf8_invalid():
    assert is_utf8(b"\x80\x81\x82") is False


# ---------------------------------------------------------------------------
# profile_bytes
# ---------------------------------------------------------------------------

def test_profile_text():
    data = (b"The quick brown fox jumps over the lazy dog. " * 20)
    p = profile_bytes(data)
    assert p.is_utf8 is True
    assert p.file_type == FileType.TEXT
    assert p.entropy > 0
    assert p.repetition_score > 0
    assert p.sample_size == len(data)


def test_profile_json():
    # Must be a single valid JSON document (not concatenated)
    payload = {"a": 1, "b": list(range(50)), "c": "hello world " * 5}
    data = json.dumps(payload).encode()
    p = profile_bytes(data)
    assert p.file_type == FileType.JSON
    assert p.is_utf8 is True


def test_profile_already_compressed():
    data = b"\x1f\x8b" + b"\x00" * 200
    p = profile_bytes(data)
    assert p.file_type == FileType.COMPRESSED
    assert p.semantic_score == 0.0


def test_profile_empty():
    p = profile_bytes(b"")
    assert p.sample_size == 0


def test_profile_semantic_score_positive_for_text():
    """Repetitive natural text should receive a positive semantic score."""
    text_data = b"the the the the dog dog dog fox fox quick quick " * 30
    p = profile_bytes(text_data)
    assert p.semantic_score > 0.0


def test_profile_semantic_score_zero_for_compressed():
    """Already-compressed data must get semantic_score == 0."""
    p = profile_bytes(b"\x1f\x8b" + b"\x00" * 200)
    assert p.semantic_score == 0.0


def test_profile_file(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("Hello world " * 100, encoding="utf-8")
    p = profile_file(f)
    assert p.file_type == FileType.TEXT
    assert p.is_utf8 is True
    assert p.entropy > 0


def test_profile_file_not_found():
    p = profile_file("/nonexistent/path/to/file.txt")
    assert p.sample_size == 0
