"""
End-to-end tests for alphamap.pipeline.Pipeline.

These tests exercise the full stack:
    file → analysis → strategy → compress → (encrypt) → write .amap
    .amap → read header → (decrypt) → decompress → original bytes

Every test verifies that recovered == original_data (byte-exact).
"""

import os
import pytest
from alphamap.pipeline.engine import Pipeline
from alphamap.core.errors import (
    DecryptionError, CorruptionError, BadMagicError, DictionaryError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PROSE = (
    "It was the best of times, it was the worst of times, "
    "it was the age of wisdom, it was the age of foolishness, "
    "it was the epoch of belief, it was the epoch of incredulity, "
    "it was the season of Light, it was the season of Darkness, "
    "it was the spring of hope, it was the winter of despair. "
) * 30


@pytest.fixture
def prose_file(tmp_path):
    f = tmp_path / "prose.txt"
    f.write_bytes(PROSE.encode("utf-8"))
    return str(f)


@pytest.fixture
def binary_file(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(bytes(i % 251 for i in range(4096)))
    return str(f)


@pytest.fixture
def json_file(tmp_path):
    import json
    data = {"items": [{"id": i, "name": f"item_{i}", "value": i * 3.14} for i in range(100)]}
    f = tmp_path / "data.json"
    f.write_bytes(json.dumps(data).encode("utf-8"))
    return str(f)


# ---------------------------------------------------------------------------
# Compress + decompress (no encryption)
# ---------------------------------------------------------------------------

class TestNoEncryption:
    def test_prose_roundtrip(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "recovered.txt")
        p = Pipeline()
        stats = p.compress(prose_file, out)
        p.decompress(out, rec)
        assert open(rec, "rb").read() == open(prose_file, "rb").read()

    def test_stats_shape(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        p = Pipeline()
        stats = p.compress(prose_file, out)
        assert "original_size" in stats
        assert "compressed_size" in stats
        assert "final_size" in stats
        assert "ratio" in stats
        assert "method" in stats
        assert stats["original_size"] > 0
        assert stats["ratio"] > 0

    def test_prose_is_compressed(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        p = Pipeline()
        stats = p.compress(prose_file, out)
        assert stats["compressed_size"] < stats["original_size"]

    def test_binary_roundtrip(self, binary_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "recovered.bin")
        p = Pipeline()
        p.compress(binary_file, out)
        p.decompress(out, rec)
        assert open(rec, "rb").read() == open(binary_file, "rb").read()

    def test_json_roundtrip(self, json_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "recovered.json")
        p = Pipeline()
        p.compress(json_file, out)
        p.decompress(out, rec)
        assert open(rec, "rb").read() == open(json_file, "rb").read()

    def test_force_zlib_backend(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "rec.txt")
        p = Pipeline()
        stats = p.compress(prose_file, out, force_backend="zlib")
        assert stats["method"] == "zlib"
        p.decompress(out, rec)
        assert open(rec, "rb").read() == open(prose_file, "rb").read()

    def test_force_lzma_backend(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "rec.txt")
        p = Pipeline()
        stats = p.compress(prose_file, out, force_backend="lzma")
        assert stats["method"] == "lzma"
        p.decompress(out, rec)
        assert open(rec, "rb").read() == open(prose_file, "rb").read()

    def test_no_embed_dict_with_external_dict(self, prose_file, tmp_path):
        """Compress without embedded dict; supply dict path on decompress."""
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "rec.txt")
        dict_file = str(tmp_path / "dict.json")

        # First, train a dictionary
        from alphamap.semantic.dictionary import AlphaMap
        am = AlphaMap()
        am.train(open(prose_file).read())
        am.save(dict_file)

        p = Pipeline()
        p.compress(prose_file, out, embed_dict=False, dict_path=dict_file)
        p.decompress(out, rec, dict_path=dict_file)
        assert open(rec, "rb").read() == open(prose_file, "rb").read()


# ---------------------------------------------------------------------------
# Compress + decompress (with AES-GCM encryption)
# ---------------------------------------------------------------------------

class TestWithEncryption:
    PASSWORD = "correct-horse-battery-staple"

    def test_encrypted_roundtrip(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "rec.txt")
        p = Pipeline(password=self.PASSWORD)
        p.compress(prose_file, out)
        p.decompress(out, rec)
        assert open(rec, "rb").read() == open(prose_file, "rb").read()

    def test_wrong_password_raises(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        p = Pipeline(password=self.PASSWORD)
        p.compress(prose_file, out)
        bad = Pipeline(password="wrong-password")
        with pytest.raises(DecryptionError):
            bad.decompress(out, str(tmp_path / "rec.txt"))

    def test_no_password_on_encrypted_file_raises(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        p = Pipeline(password=self.PASSWORD)
        p.compress(prose_file, out)
        no_pass = Pipeline()
        with pytest.raises(DecryptionError):
            no_pass.decompress(out, str(tmp_path / "rec.txt"))

    def test_encrypted_file_is_not_readable_as_plaintext(self, prose_file, tmp_path):
        """The raw .amap payload must not contain the original plaintext."""
        out = str(tmp_path / "out.amap")
        p = Pipeline(password=self.PASSWORD)
        p.compress(prose_file, out)
        raw = open(out, "rb").read()
        assert PROSE[:50].encode("utf-8") not in raw

    def test_each_encryption_uses_different_nonce(self, prose_file, tmp_path):
        """Two encryptions of the same file must produce different outputs."""
        out1 = str(tmp_path / "out1.amap")
        out2 = str(tmp_path / "out2.amap")
        p = Pipeline(password=self.PASSWORD)
        p.compress(prose_file, out1)
        p.compress(prose_file, out2)
        assert open(out1, "rb").read() != open(out2, "rb").read()

    def test_binary_encrypted_roundtrip(self, binary_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "rec.bin")
        p = Pipeline(password=self.PASSWORD)
        p.compress(binary_file, out, force_backend="zlib")
        p.decompress(out, rec)
        assert open(rec, "rb").read() == open(binary_file, "rb").read()


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------

class TestInspect:
    def test_inspect_returns_metadata(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        p = Pipeline()
        p.compress(prose_file, out)
        meta = p.inspect(out)
        assert meta["version"] == 2
        assert meta["original_size"] > 0
        assert meta["encrypted"] is False

    def test_inspect_encrypted(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        p = Pipeline(password="pw")
        p.compress(prose_file, out)
        meta = p.inspect(out)
        assert meta["encrypted"] is True

    def test_inspect_filename_hint(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        p = Pipeline()
        p.compress(prose_file, out)
        meta = p.inspect(out)
        assert "prose.txt" in meta["filename"]

    def test_inspect_bad_magic(self, tmp_path):
        bad = tmp_path / "bad.amap"
        bad.write_bytes(b"XXXX" + b"\x00" * 100)
        p = Pipeline()
        with pytest.raises(BadMagicError):
            p.inspect(str(bad))


# ---------------------------------------------------------------------------
# CRC corruption detection
# ---------------------------------------------------------------------------

class TestCorruptionDetection:
    def test_corrupt_payload_detected(self, prose_file, tmp_path):
        out = str(tmp_path / "out.amap")
        rec = str(tmp_path / "rec.txt")
        p = Pipeline()
        stats = p.compress(prose_file, out, force_backend="zlib")

        # Flip bits in the middle of the file (after the header)
        raw = bytearray(open(out, "rb").read())
        mid = len(raw) // 2
        raw[mid] ^= 0xFF
        open(out, "wb").write(raw)

        with pytest.raises((CorruptionError, Exception)):
            p.decompress(out, rec)
