"""
AbstractBackend: the interface every compression backend must satisfy.

Design goals:
  - Each backend is stateless after construction.
  - compress() / decompress() operate on bytes, not files or str.
    Text encoding/decoding is the caller's responsibility.
  - Backends do not know about encryption, headers, or dictionaries.
  - The registry allows strategy.selector to iterate available backends
    without importing them individually.
"""

from __future__ import annotations

import abc
from typing import ClassVar, Dict, Type


class AbstractBackend(abc.ABC):
    """Base class for all compression backends.

    Subclass and implement :meth:`compress` and :meth:`decompress`.
    Then register with :func:`register_backend`.
    """

    #: Short unique name used in CLI flags and benchmark labels.
    #: Must be set by every concrete subclass.
    name: ClassVar[str] = ""

    @abc.abstractmethod
    def compress(self, data: bytes) -> bytes:
        """Return the compressed form of *data*."""

    @abc.abstractmethod
    def decompress(self, data: bytes) -> bytes:
        """Return the original *data* from its compressed form."""

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"


# ---------------------------------------------------------------------------
# Backend registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, Type[AbstractBackend]] = {}


def register_backend(cls: Type[AbstractBackend]) -> Type[AbstractBackend]:
    """Class decorator — register *cls* in the global backend registry.

    Usage::

        @register_backend
        class BrotliBackend(AbstractBackend):
            name = "brotli"
            ...
    """
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty `name` attribute")
    _REGISTRY[cls.name] = cls
    return cls


def get_backend(name: str) -> AbstractBackend:
    """Return an instance of the backend registered under *name*.

    Raises :class:`KeyError` if no backend with that name is registered.
    """
    if name not in _REGISTRY:
        raise KeyError(
            f"No backend named {name!r}. "
            f"Available: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]()


def list_backends() -> list[str]:
    """Return names of all registered backends (sorted)."""
    return sorted(_REGISTRY)
