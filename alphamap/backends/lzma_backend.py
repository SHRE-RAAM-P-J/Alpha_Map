"""lzma compression backend."""

import lzma

from .base import AbstractBackend, register_backend


@register_backend
class LzmaBackend(AbstractBackend):
    """lzma with LZMA2 format (best ratio, slow)."""

    name = "lzma"

    def compress(self, data: bytes) -> bytes:
        return lzma.compress(data, format=lzma.FORMAT_XZ)

    def decompress(self, data: bytes) -> bytes:
        return lzma.decompress(data)
