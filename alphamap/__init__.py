"""
AlphaMap v2 — adaptive hybrid compression engine.

Quick start::

    from alphamap import Pipeline

    p = Pipeline(password="secret")
    stats = p.compress("notes.txt", "notes.amap")
    p.decompress("notes.amap", "notes_recovered.txt")

Backward-compatible API (v1 names still work)::

    from alphamap import AlphaMap, AlphaMapStream
    stream = AlphaMapStream("my-password")
    stream.encrypt("notes.txt", "notes.am11")
    stream.decrypt("notes.am11", "notes_recovered.txt")

From the command line::

    alphamap compress notes.txt -k my-password
    alphamap decompress notes.amap -k my-password
    alphamap analyze data.json
    alphamap benchmark corpus.txt
"""

from .pipeline.engine import Pipeline
from .semantic.dictionary import AlphaMap, tokenize
from .semantic.bitpacking import BitReader, BitWriter
from .crypto.kdf import derive_key
from .core.constants import DEFAULT_DICT_LIMIT
from .core.errors import AlphaMapError


class AlphaMapStream:
    """
    v1-compatible high-level encrypt/decrypt interface.

    Delegates to Pipeline internally.  Existing code using
    stream.encrypt() / stream.decrypt() works unchanged.
    """

    def __init__(self, password: str) -> None:
        self._pipeline = Pipeline(password=password)

    def encrypt(self, input_path, output_path, embed_dict=True, dict_path=None):
        stats = self._pipeline.compress(
            input_path, output_path,
            embed_dict=embed_dict,
            dict_path=dict_path,
        )
        original = stats["original_size"]
        final = stats["final_size"]
        print(f"Original : {original:,} bytes")
        print(f"Encrypted: {final:,} bytes ({100 * final / original:.1f}%)")
        print(f"Method   : {stats['method']}")

    def decrypt(self, input_path, output_path, dict_path=None):
        self._pipeline.decompress(input_path, output_path, dict_path=dict_path)


class CompressionEngine:
    """v1-compatible compression wrapper. Use Pipeline for new code."""

    def __init__(self, alphamap):
        from .backends.semantic_backend import SemanticBackend
        self._backend = SemanticBackend()
        if alphamap.word_to_id:
            self._backend.set_word_map(alphamap.word_to_id, alphamap.dict_limit)

    def compress(self, text: str):
        import zlib
        from .core.constants import FLAG_ZLIB_FALLBACK
        data = text.encode("utf-8")
        try:
            am_bytes = self._backend.compress(data)
        except Exception:
            am_bytes = None
        zl_bytes = zlib.compress(data, level=9)
        if am_bytes and len(am_bytes) < len(zl_bytes):
            return am_bytes, 0
        return zl_bytes, FLAG_ZLIB_FALLBACK

    def decompress(self, data: bytes, flags: int) -> str:
        import zlib
        from .core.constants import FLAG_ZLIB_FALLBACK
        if flags & FLAG_ZLIB_FALLBACK:
            return zlib.decompress(data).decode("utf-8")
        return self._backend.decompress(data).decode("utf-8")


__version__ = "0.2.0"
__author__ = "AlphaMap contributors"

__all__ = [
    "Pipeline",
    "AlphaMap", "AlphaMapStream", "CompressionEngine",
    "BitReader", "BitWriter",
    "tokenize", "derive_key",
    "DEFAULT_DICT_LIMIT", "AlphaMapError",
]
