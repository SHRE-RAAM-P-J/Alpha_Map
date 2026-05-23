"""gzip compression backend."""

import gzip

from .base import AbstractBackend, register_backend


@register_backend
class GzipBackend(AbstractBackend):
    """gzip at compresslevel 9."""

    name = "gzip"

    def __init__(self, level: int = 9) -> None:
        self._level = level

    def compress(self, data: bytes) -> bytes:
        return gzip.compress(data, compresslevel=self._level)

    def decompress(self, data: bytes) -> bytes:
        return gzip.decompress(data)
