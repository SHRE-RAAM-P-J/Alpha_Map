"""
AlphaMap dictionary: trains on a text corpus, maps tokens → integer IDs,
and encodes/decodes lists of tokens to compact bit-packed bytes.

What's kept from v1 (unchanged logic):
    - tokenize()             — regex split on whitespace/non-whitespace runs
    - bits_required()        — bit-length calculation
    - AlphaMap.train()       — frequency-sorted word list, whitespace boost
    - AlphaMap.encode_case() / apply_case()  — 2-bit case encoding
    - AlphaMap.encode_tokens() / decode_tokens() — bit-packing with OOV escape
    - AlphaMap.save() / load()  — JSON persistence

What changed:
    - Import path: was alphamap.dictionary, now alphamap.semantic.dictionary
    - Imports BitWriter/BitReader from .bitpacking (same package)
    - Imports constants from alphamap.core (no magic literals)
    - Error types replaced with AlphaMap typed exceptions
    - save_dictionary / load_dictionary aliases retained for backward compat
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Dict, List, Optional

from .bitpacking import BitWriter, BitReader
from ..core.constants import DEFAULT_DICT_LIMIT, MAX_TOKEN_BYTES
from ..core.errors import DictionaryError, TokenTooLongError

# Dictionary file schema version — bump when the JSON shape changes
_DICT_VERSION = 1

# Tokeniser: a token is either a maximal run of non-whitespace OR
# a maximal run of whitespace.  This guarantees a lossless round-trip:
# ''.join(tokenize(text)) == text for all text.
_TOKEN_RE = re.compile(r"\S+|\s+")


def tokenize(text: str) -> List[str]:
    """Split *text* into tokens (words and whitespace runs).

    The split is lossless: ``''.join(tokenize(t)) == t`` for all *t*.
    """
    return _TOKEN_RE.findall(text)


def bits_required(n: int) -> int:
    """Minimum bits needed to represent the non-negative integer *n*."""
    return 1 if n == 0 else n.bit_length()


class AlphaMap:
    """
    Dictionary-based text encoder with bit-packing.

    Typical usage::

        am = AlphaMap()
        am.train(corpus_text)
        tokens = tokenize(input_text)
        encoded = am.encode_tokens(tokens)
        recovered = am.decode_tokens(encoded, len(tokens))
        assert recovered == tokens
    """

    def __init__(self, dict_limit: int = DEFAULT_DICT_LIMIT) -> None:
        self.word_to_id: Dict[str, int] = {}
        self.id_to_word: Dict[int, str] = {}
        self.dict_limit: int = dict_limit
        self.word_id_bits: int = bits_required(dict_limit)
        self.case_bits: int = 2            # 2 bits → 0=lower 1=title 2=upper
        self.oov_id: int = dict_limit      # one past the last valid ID

    # ------------------------------------------------------------------
    # Training and persistence
    # ------------------------------------------------------------------

    def train(self, text: str, limit: Optional[int] = None) -> None:
        """Build the dictionary from *text*, keeping the *limit* most-frequent tokens.

        Whitespace tokens are boosted (×10) so they get low IDs and cost
        fewer bits to encode — they appear in nearly every sentence.
        """
        limit = limit if limit is not None else self.dict_limit
        freq: Counter = Counter()
        for token in tokenize(text.lower()):
            freq[token] += 10 if not token.strip() else 1
        top = freq.most_common(limit)
        self.word_to_id = {word: idx for idx, (word, _) in enumerate(top)}
        self.id_to_word = {idx: word for word, idx in self.word_to_id.items()}

    def save(self, path: str) -> None:
        """Persist the dictionary to a JSON file at *path*."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"version": _DICT_VERSION, "limit": self.dict_limit,
                 "words": self.word_to_id},
                fh, ensure_ascii=False, indent=2,
            )

    def load(self, path: str) -> None:
        """Load a dictionary previously saved with :meth:`save`."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("version") != _DICT_VERSION:
            raise DictionaryError(
                f"Dictionary version {data.get('version')} != {_DICT_VERSION}"
            )
        self.word_to_id = data["words"]
        self.id_to_word = {int(idx): word for word, idx in self.word_to_id.items()}
        self.dict_limit = data.get("limit", len(self.word_to_id))

    # Backward-compatible aliases (used by old CLI code and phase4.py)
    def save_dictionary(self, path: str) -> None:  # pragma: no cover
        self.save(path)

    def load_dictionary(self, path: str) -> None:  # pragma: no cover
        self.load(path)

    # ------------------------------------------------------------------
    # Case helpers
    # ------------------------------------------------------------------

    @staticmethod
    def encode_case(word: str) -> int:
        """Return 0 (lower), 1 (title), or 2 (upper) for *word*."""
        if not word:
            return 0
        if word.isupper():
            return 2
        if word[0].isupper():
            return 1
        return 0

    @staticmethod
    def apply_case(word: str, case: int) -> str:
        """Reconstruct the correct casing given the canonical lowercase *word*."""
        if case == 2:
            return word.upper()
        if case == 1:
            return word.capitalize()
        return word.lower()

    # ------------------------------------------------------------------
    # Encode / decode
    # ------------------------------------------------------------------

    def encode_tokens(self, tokens: List[str]) -> bytes:
        """Encode *tokens* to a compact bit-packed byte string.

        Format per token:
            word_id  : word_id_bits + 1   bits
            case     : 2                  bits
            [OOV only]
            length   : 8                  bits  (byte count of UTF-8)
            raw_bytes: length × 8         bits
        """
        writer = BitWriter()
        for token in tokens:
            case = self.encode_case(token)
            lower = token.lower()
            word_id = self.word_to_id.get(lower, self.oov_id)
            writer.write_bits(word_id, self.word_id_bits + 1)
            writer.write_bits(case, self.case_bits)
            if word_id == self.oov_id:
                token_bytes = lower.encode("utf-8")
                if len(token_bytes) > MAX_TOKEN_BYTES:
                    raise TokenTooLongError(
                        f"OOV token exceeds {MAX_TOKEN_BYTES} bytes: {token[:40]!r}…"
                    )
                writer.write_bits(len(token_bytes), 8)
                for byte in token_bytes:
                    writer.write_bits(byte, 8)
        return writer.flush()

    def decode_tokens(self, data: bytes, num_tokens: int) -> List[str]:
        """Decode bit-packed *data* back to a list of *num_tokens* tokens."""
        reader = BitReader(data)
        tokens: List[str] = []
        for _ in range(num_tokens):
            word_id = reader.read_bits(self.word_id_bits + 1)
            case = reader.read_bits(self.case_bits)
            if word_id == self.oov_id:
                length = reader.read_bits(8)
                word = bytes(reader.read_bits(8) for _ in range(length)).decode("utf-8")
            else:
                word = self.id_to_word.get(word_id, "<?>")
            tokens.append(self.apply_case(word, case))
        return tokens
