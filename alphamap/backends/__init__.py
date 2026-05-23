"""
AlphaMap compression backends.

Importing this package causes all backends to register themselves
in the global registry (via the @register_backend decorator), so
strategy.selector can query them by name.
"""

from .base import AbstractBackend, register_backend, get_backend, list_backends

# Import each backend to trigger its @register_backend decorator.
# Order does not matter for correctness.
from . import zlib_backend      # noqa: F401
from . import gzip_backend      # noqa: F401
from . import lzma_backend      # noqa: F401
from . import brotli_backend    # noqa: F401  (silently skipped if brotli not installed)
from . import semantic_backend  # noqa: F401

from .semantic_backend import SemanticBackend
from .zlib_backend import ZlibBackend
from .gzip_backend import GzipBackend
from .lzma_backend import LzmaBackend

__all__ = [
    "AbstractBackend",
    "register_backend",
    "get_backend",
    "list_backends",
    "SemanticBackend",
    "ZlibBackend",
    "GzipBackend",
    "LzmaBackend",
]
