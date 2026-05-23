"""
Semantic compression backend.

Wraps the AlphaMap dictionary encoder behind the AbstractBackend interface.
The backend is *stateful* in one way: after calling compress() the trained
dictionary is stored and must be provided to decompress().  The pipeline
layer handles serialising the dictionary into the container header.

compress(data: bytes) → bytes
    Interprets *data* as UTF-8 text.
    Returns:  struct.pack("I", num_tokens) + bit-packed token stream

decompress(data: bytes) → bytes
    Returns the reconstructed UTF-8 bytes.
    Requires that load_dictionary() or set_word_map() was called first.
"""

from __future__ import annotations

import struct
from typing import Optional

from .base import AbstractBackend, register_backend
from ..semantic.dictionary import AlphaMap, tokenize
from ..core.constants import DEFAULT_DICT_LIMIT
from ..core.errors import DictionaryError, CompressionError


@register_backend
class SemanticBackend(AbstractBackend):
    """AlphaMap dictionary-based token compression."""

    name = "alphamap"

    def __init__(self, dict_limit: int = DEFAULT_DICT_LIMIT) -> None:
        self._am = AlphaMap(dict_limit=dict_limit)

    # ------------------------------------------------------------------
    # AbstractBackend interface
    # ------------------------------------------------------------------

    def compress(self, data: bytes) -> bytes:
        """Train on *data* (UTF-8 text) and return the encoded payload.

        Side-effect: trains the internal dictionary.  The caller is
        responsible for serialising ``self.word_to_id`` into the container
        header if the compressed bytes are to be stored persistently.
        """
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CompressionError("SemanticBackend requires UTF-8 input") from exc

        if not self._am.word_to_id:
            self._am.train(text)

        tokens = tokenize(text)
        token_data = self._am.encode_tokens(tokens)
        return struct.pack("<I", len(tokens)) + token_data

    def decompress(self, data: bytes) -> bytes:
        """Decode *data* back to UTF-8 text bytes.

        Requires that the dictionary was already loaded via
        :meth:`set_word_map` or :meth:`load_dictionary`.
        """
        if not self._am.word_to_id:
            raise DictionaryError(
                "SemanticBackend: no dictionary loaded — call set_word_map() first"
            )
        num_tokens = struct.unpack("<I", data[:4])[0]
        tokens = self._am.decode_tokens(data[4:], num_tokens)
        return "".join(tokens).encode("utf-8")

    # ------------------------------------------------------------------
    # Dictionary access (used by formats layer)
    # ------------------------------------------------------------------

    @property
    def word_to_id(self) -> dict:
        return self._am.word_to_id

    @property
    def dict_limit(self) -> int:
        return self._am.dict_limit

    def set_word_map(self, word_to_id: dict, dict_limit: int) -> None:
        """Restore dictionary state from a deserialized header."""
        self._am.word_to_id = word_to_id
        self._am.dict_limit = dict_limit
        self._am.id_to_word = {int(v): k for k, v in word_to_id.items()}

    def load_dictionary(self, path: str) -> None:
        self._am.load(path)

    def save_dictionary(self, path: str) -> None:
        self._am.save(path)

    def train(self, text: str) -> None:
        """Train the dictionary on *text* without compressing."""
        self._am.train(text)
