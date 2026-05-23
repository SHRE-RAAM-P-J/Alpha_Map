"""brotli compression backend (optional dependency)."""

from .base import AbstractBackend, register_backend

try:
    import brotli as _brotli
    _BROTLI_AVAILABLE = True
except ImportError:  # pragma: no cover
    _BROTLI_AVAILABLE = False


if _BROTLI_AVAILABLE:
    @register_backend
    class BrotliBackend(AbstractBackend):
        """brotli at quality 11 (maximum compression)."""

        name = "brotli"

        def __init__(self, quality: int = 11) -> None:
            self._quality = quality

        def compress(self, data: bytes) -> bytes:
            return _brotli.compress(data, quality=self._quality)

        def decompress(self, data: bytes) -> bytes:
            return _brotli.decompress(data)
