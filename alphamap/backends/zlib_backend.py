"""zlib compression backend."""

import zlib

from .base import AbstractBackend, register_backend


@register_backend
class ZlibBackend(AbstractBackend):
    """zlib (DEFLATE) at level 9."""

    name = "zlib"

    def __init__(self, level: int = 9) -> None:
        self._level = level

    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data, self._level)

    def decompress(self, data: bytes) -> bytes:
        return zlib.decompress(data)
