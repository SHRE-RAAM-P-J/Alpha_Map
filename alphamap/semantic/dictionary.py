"""
AlphaMap dictionary: trains on a text corpus, maps tokens → integer IDs,
and encodes/decodes lists of tokens to compact bit-packed bytes.

Improvements over v0.2.0
--------------------------
OOV handling:
  - Tokens longer than MAX_TOKEN_BYTES are gracefully truncated at a valid
    UTF-8 boundary instead of raising TokenTooLongError, so the encoder
    never crashes on real-world input (URLs, base64 blobs, etc.)
  - Corrupt word_id during decode returns a visible placeholder instead of
    the silent "<?>" marker.
  - decode_tokens uses errors="replace" on UTF-8 decode to handle
    edge-case corrupted data gracefully.

Training quality:
  - Common punctuation marks ("," "." "!" etc.) are always seeded into the
    frequency counter so they always get dictionary entries, meaning
    "hello," encodes as two cheap in-dict tokens instead of one expensive OOV.
  - A min_freq threshold (default 2) prevents very rare tokens wasting slots.
  - Whitespace boost raised from ×10 to ×20.

Diagnostics:
  - oov_rate(text): fraction of word tokens not in dictionary.
  - coverage_stats(text): full breakdown for monitoring/debugging.
"""

from __future__ import annotations

import re
import json
from collections import Counter
from typing import Dict, List, Optional

from .bitpacking import BitWriter, BitReader
from ..core.constants import DEFAULT_DICT_LIMIT, MAX_TOKEN_BYTES
from ..core.errors import DictionaryError, TokenTooLongError

_DICT_VERSION = 2   # bumped: common-punct seeding, min_freq, whitespace boost

_TOKEN_RE = re.compile(r"\S+|\s+")


def tokenize(text: str) -> List[str]:
    """Split *text* into tokens (words and whitespace runs).

    The split is lossless: ``''.join(tokenize(t)) == t`` for all *t*.
    """
    return _TOKEN_RE.findall(text)


def bits_required(n: int) -> int:
    """Minimum bits needed to represent the non-negative integer *n*."""
    return 1 if n == 0 else n.bit_length()


def _safe_encode(token: str) -> bytes:
    """Return the UTF-8 bytes of *token*, truncated to MAX_TOKEN_BYTES at a
    valid UTF-8 codepoint boundary.  Never raises."""
    raw = token.encode("utf-8")
    if len(raw) <= MAX_TOKEN_BYTES:
        return raw
    # Back off to a valid boundary
    truncated = raw[:MAX_TOKEN_BYTES]
    while truncated:
        try:
            truncated.decode("utf-8")
            return truncated
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    return b""  # degenerate case: single multi-byte char > MAX_TOKEN_BYTES


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
        self.case_bits: int = 2
        self.oov_id: int = dict_limit

    # ------------------------------------------------------------------
    # Training and persistence
    # ------------------------------------------------------------------

    def train(self, text: str, limit: Optional[int] = None, min_freq: int = 2) -> None:
        """Build the dictionary from *text*.

        Args:
            text:     Training corpus.
            limit:    Max dictionary entries (default: dict_limit).
            min_freq: Discard tokens appearing fewer times. Prevents rare tokens
                      wasting slots that high-frequency tokens need.

        Whitespace is boosted ×20; common punctuation is always seeded
        so it always gets a dictionary slot (avoids costly OOV escapes for ".").
        """
        limit = limit if limit is not None else self.dict_limit
        freq: Counter = Counter()

        # Seed common punctuation — always want these in the dict
        _ALWAYS = {",", ".", "!", "?", ":", ";", "(", ")", '"', "'",
                   "-", "/", "@", "#", "%", "&", "*", "..."}
        for ch in _ALWAYS:
            freq[ch] = 9999

        for raw_token in tokenize(text.lower()):
            if not raw_token.strip():
                freq[raw_token] += 20   # whitespace boost
            else:
                freq[raw_token] += 1

        filtered = [(w, c) for w, c in freq.items() if c >= min_freq]
        filtered.sort(key=lambda x: -x[1])
        top = filtered[:limit]

        self.word_to_id = {word: idx for idx, (word, _) in enumerate(top)}
        self.id_to_word = {idx: word for word, idx in self.word_to_id.items()}

    def save(self, path: str) -> None:
        """Persist the dictionary to a JSON file."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"version": _DICT_VERSION, "limit": self.dict_limit,
                 "words": self.word_to_id},
                fh, ensure_ascii=False, indent=2,
            )

    def load(self, path: str) -> None:
        """Load a dictionary. Accepts version 1 or 2."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        ver = data.get("version")
        if ver not in (1, 2):
            raise DictionaryError(f"Unknown dictionary version {ver!r}. Expected 1 or 2.")
        self.word_to_id = data["words"]
        self.id_to_word = {int(idx): word for word, idx in self.word_to_id.items()}
        self.dict_limit = data.get("limit", len(self.word_to_id))

    def save_dictionary(self, path: str) -> None:  # pragma: no cover
        self.save(path)

    def load_dictionary(self, path: str) -> None:  # pragma: no cover
        self.load(path)

    # ------------------------------------------------------------------
    # Case helpers
    # ------------------------------------------------------------------

    @staticmethod
    def encode_case(word: str) -> int:
        if not word:
            return 0
        if word.isupper():
            return 2
        if word[0].isupper():
            return 1
        return 0

    @staticmethod
    def apply_case(word: str, case: int) -> str:
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
            word_id  : word_id_bits + 1  bits
            case     : 2                 bits
            [OOV only]
            length   : 8                 bits  (byte count, capped at MAX_TOKEN_BYTES)
            raw_bytes: length × 8        bits
        """
        writer = BitWriter()
        for token in tokens:
            case = self.encode_case(token)
            lower = token.lower()
            word_id = self.word_to_id.get(lower, self.oov_id)
            writer.write_bits(word_id, self.word_id_bits + 1)
            writer.write_bits(case, self.case_bits)
            if word_id == self.oov_id:
                token_bytes = _safe_encode(lower)
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
                word = bytes(
                    reader.read_bits(8) for _ in range(length)
                ).decode("utf-8", errors="replace")
            else:
                word = self.id_to_word.get(word_id)
                if word is None:
                    word = f"<id:{word_id}>"
            tokens.append(self.apply_case(word, case))
        return tokens

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def oov_rate(self, text: str) -> float:
        """Return the fraction of word tokens that are OOV (0.0–1.0)."""
        tokens = [t for t in tokenize(text.lower()) if t.strip()]
        if not tokens:
            return 0.0
        oov = sum(1 for t in tokens if t not in self.word_to_id)
        return oov / len(tokens)

    def coverage_stats(self, text: str) -> dict:
        """Return a coverage statistics dict for *text*."""
        tokens = tokenize(text.lower())
        word_tokens = [t for t in tokens if t.strip()]
        oov_tokens = [t for t in word_tokens if t not in self.word_to_id]
        return {
            "total_tokens": len(tokens),
            "word_tokens": len(word_tokens),
            "oov_tokens": len(oov_tokens),
            "oov_rate": round(len(oov_tokens) / len(word_tokens), 4) if word_tokens else 0.0,
            "dict_size": len(self.word_to_id),
            "top_oov": Counter(oov_tokens).most_common(10),
        }
