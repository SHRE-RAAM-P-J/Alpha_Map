"""
Backward-compatibility tests.

These ensure that v1 call-sites (AlphaMapStream, CompressionEngine) still
work after the v2 refactor.  No v1 code should need modification.
"""

import pytest
from alphamap import AlphaMapStream, CompressionEngine, AlphaMap


PROSE = (
    "In the beginning the Universe was created. "
    "This has made a lot of people very angry and been widely regarded "
    "as a bad move. "
) * 40


class TestAlphaMapStream:
    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        src = tmp_path / "input.txt"
        enc = tmp_path / "encrypted.amap"
        dec = tmp_path / "decrypted.txt"
        src.write_bytes(PROSE.encode("utf-8"))

        stream = AlphaMapStream("secret-password")
        stream.encrypt(str(src), str(enc))
        stream.decrypt(str(enc), str(dec))

        assert dec.read_bytes() == src.read_bytes()

    def test_wrong_password_raises(self, tmp_path):
        src = tmp_path / "input.txt"
        enc = tmp_path / "enc.amap"
        src.write_bytes(PROSE.encode("utf-8"))

        AlphaMapStream("correct").encrypt(str(src), str(enc))

        from alphamap.core.errors import DecryptionError
        with pytest.raises(DecryptionError):
            AlphaMapStream("wrong").decrypt(str(enc), str(tmp_path / "out.txt"))

    def test_encrypt_produces_file(self, tmp_path):
        src = tmp_path / "input.txt"
        enc = tmp_path / "encrypted.amap"
        src.write_bytes(PROSE.encode("utf-8"))
        AlphaMapStream("pw").encrypt(str(src), str(enc))
        assert enc.exists()
        assert enc.stat().st_size > 0

    def test_encrypt_prints_stats(self, tmp_path, capsys):
        src = tmp_path / "input.txt"
        enc = tmp_path / "enc.amap"
        src.write_bytes(PROSE.encode("utf-8"))
        AlphaMapStream("pw").encrypt(str(src), str(enc))
        out = capsys.readouterr().out
        assert "Original" in out
        assert "Encrypted" in out


class TestCompressionEngine:
    def test_compress_decompress_roundtrip(self):
        am = AlphaMap()
        am.train(PROSE)
        engine = CompressionEngine(am)
        compressed, flags = engine.compress(PROSE)
        recovered = engine.decompress(compressed, flags)
        assert recovered == PROSE

    def test_returns_bytes_and_flags(self):
        am = AlphaMap()
        am.train(PROSE)
        engine = CompressionEngine(am)
        compressed, flags = engine.compress(PROSE)
        assert isinstance(compressed, bytes)
        assert isinstance(flags, int)

    def test_compressed_smaller_than_original(self):
        am = AlphaMap()
        am.train(PROSE)
        engine = CompressionEngine(am)
        compressed, _ = engine.compress(PROSE)
        assert len(compressed) < len(PROSE.encode("utf-8"))
