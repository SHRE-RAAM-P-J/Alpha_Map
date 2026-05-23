"""
File type detection via magic bytes and heuristics.

We deliberately avoid the python-magic / libmagic dependency so the
package stays pip-installable anywhere without a C library.  The
detection is heuristic-grade, not MIME-specification-grade — good
enough to drive compression strategy decisions.

Detection order (first match wins):
    1. Known compressed-format magic bytes → FileType.COMPRESSED
    2. UTF-8 validity check
    3. JSON structure heuristic
    4. CSV structure heuristic
    5. Source code heuristic (shebangs, common keywords)
    6. Word ratio heuristic → TEXT vs BINARY vs UNKNOWN
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Union

from ..core.types import FileType
from ..core.constants import SAMPLE_BYTES


# Magic-byte signatures for already-compressed formats.
# We skip compression entirely for these — entropy will be near 8.0 anyway.
_COMPRESSED_MAGIC: list[bytes] = [
    b"\x1f\x8b",          # gzip
    b"BZh",               # bzip2
    b"\xfd7zXZ\x00",      # xz / lzma
    b"PK\x03\x04",        # zip
    b"Rar!",              # rar
    b"\x28\xb5\x2f\xfd",  # zstd
    b"\x04\x22\x4d\x18",  # lz4
    b"AMAP",              # our own format
    b"AM11",              # our own format (v1)
]

# Source-code indicators (extension-agnostic heuristics)
_SOURCE_KEYWORDS = [
    b"def ", b"class ", b"import ", b"#include", b"function ",
    b"public ", b"private ", b"void ", b"return ", b"if (",
    b"for (", b"while (", b"const ", b"let ", b"var ",
]


def detect_file_type(path: Union[str, Path]) -> FileType:
    """Detect the type of the file at *path* from its content.

    Reads at most ``SAMPLE_BYTES`` from the start of the file.
    """
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            sample = fh.read(SAMPLE_BYTES)
    except OSError:
        return FileType.UNKNOWN

    return detect_bytes_type(sample)


def detect_bytes_type(sample: bytes) -> FileType:
    """Detect the type of *sample* (a leading slice of file content)."""

    # --- 1. Compressed magic bytes ---
    for magic in _COMPRESSED_MAGIC:
        if sample.startswith(magic):
            return FileType.COMPRESSED

    # --- 2. UTF-8 validity ---
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return FileType.BINARY

    # --- 3. JSON ---
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(text)
            return FileType.JSON
        except json.JSONDecodeError:
            pass  # might still be partial JSON at sample boundary

    # --- 4. CSV: at least two lines, same number of commas each ---
    lines = text.splitlines()
    if len(lines) >= 3:
        comma_counts = [line.count(",") for line in lines[:5] if line.strip()]
        if comma_counts and len(set(comma_counts)) == 1 and comma_counts[0] >= 1:
            return FileType.CSV

    # --- 5. Source code ---
    sample_lower = sample.lower()
    if any(kw in sample_lower for kw in _SOURCE_KEYWORDS):
        return FileType.SOURCE

    # --- 6. Natural-language text: high word ratio ---
    words = text.split()
    if words:
        # Ratio of "word-like" tokens (alpha/digit) to total split tokens
        word_like = sum(1 for w in words if any(c.isalpha() for c in w))
        if word_like / len(words) > 0.70:
            return FileType.TEXT

    return FileType.UNKNOWN


def is_utf8(data: bytes) -> bool:
    """Return True if *data* decodes cleanly as UTF-8."""
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def mime_hint(path: Union[str, Path]) -> str:
    """Return a best-guess MIME string from the file extension alone."""
    ext = Path(path).suffix.lower()
    _EXT_MAP = {
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".json": "application/json",
        ".csv": "text/csv",
        ".xml": "application/xml",
        ".html": "text/html",
        ".htm": "text/html",
        ".py": "text/x-python",
        ".js": "text/javascript",
        ".ts": "text/typescript",
        ".c": "text/x-c",
        ".cpp": "text/x-c++",
        ".gz": "application/gzip",
        ".zip": "application/zip",
        ".xz": "application/x-xz",
        ".bz2": "application/x-bzip2",
        ".amap": "application/x-alphamap",
        ".am11": "application/x-alphamap",
    }
    return _EXT_MAP.get(ext, "application/octet-stream")
