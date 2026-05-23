"""
.amap v2 container header: serialisation and deserialisation.

Header layout on disk (all integers little-endian):

    MAGIC        4 bytes  b"AMAP"  (or b"AM11" for v1 files)
    VERSION      1 byte   uint8    format version (2 for v2)
    FLAGS        2 bytes  uint16   bitmask (see core.constants FLAG_*)
    SALT         16 bytes          PBKDF2 salt (zeros if not encrypted)
    NONCE        12 bytes          AES-GCM nonce (zeros if not encrypted)
    HEADER_LEN   4 bytes  uint32   byte length of the variable header blob
    HEADER_BLOB  variable bytes    JSON-encoded metadata dict
    PAYLOAD      variable bytes    compressed (+ optionally encrypted) data
    TAG          16 bytes          AES-GCM authentication tag (zeros if not encrypted)

The variable HEADER_BLOB is a UTF-8 JSON object containing:
    method      int     CompressionMethod value
    orig_size   int     original plaintext byte count
    crc32       int     CRC32 of (header_blob + compressed_payload) before encryption
    dict        object  {"limit": int, "words": {str: int}} or null
    filename    str     original filename hint (may be empty)
    created_at  int     unix timestamp (seconds)

Notes:
    - TAG is all-zero bytes when encryption is disabled (FLAG_ENCRYPTED not set).
    - SALT and NONCE are all-zero bytes when encryption is disabled.
    - The JSON blob intentionally stays human-readable for now.
      A MessagePack upgrade is planned for v3 (see roadmap).
"""

from __future__ import annotations

import json
import struct
import time
from dataclasses import asdict, dataclass
from typing import Optional

from ..core.constants import (
    MAGIC, MAGIC_V1, FORMAT_VERSION,
    SALT_SIZE, NONCE_SIZE, TAG_SIZE,
    FLAG_EMBEDDED_DICT, FLAG_ENCRYPTED,
)
from ..core.errors import BadMagicError, UnsupportedVersionError
from ..core.types import CompressionMethod


# Fixed-size prefix before the variable blob
# MAGIC(4) + VERSION(1) + FLAGS(2) + SALT(16) + NONCE(12) + HEADER_LEN(4) = 39 bytes
_FIXED_PREFIX_FMT = "<4sBH16s12sI"   # little-endian
_FIXED_PREFIX_SIZE = struct.calcsize(_FIXED_PREFIX_FMT)  # 39


@dataclass
class AmapHeader:
    """Parsed representation of a .amap file header."""
    version: int
    flags: int
    salt: bytes
    nonce: bytes
    # from the variable blob:
    method: CompressionMethod = CompressionMethod.ALPHAMAP
    original_size: int = 0
    crc32: int = 0
    dict_data: Optional[dict] = None   # {"limit": int, "words": {...}} or None
    filename: str = ""
    created_at: int = 0

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def has_embedded_dict(self) -> bool:
        return bool(self.flags & FLAG_EMBEDDED_DICT)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def build_header_blob(header: AmapHeader) -> bytes:
    """Serialise the variable-length header blob to UTF-8 JSON bytes."""
    obj = {
        "method": int(header.method),
        "orig_size": header.original_size,
        "crc32": header.crc32,
        "dict": header.dict_data,
        "filename": header.filename,
        "created_at": header.created_at or int(time.time()),
    }
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write_fixed_prefix(
    fh,
    flags: int,
    salt: bytes,
    nonce: bytes,
    header_blob: bytes,
) -> None:
    """Write the fixed 39-byte prefix and the header blob to an open file handle."""
    fh.write(struct.pack(
        _FIXED_PREFIX_FMT,
        MAGIC,
        FORMAT_VERSION,
        flags,
        salt.ljust(SALT_SIZE, b"\x00")[:SALT_SIZE],
        nonce.ljust(NONCE_SIZE, b"\x00")[:NONCE_SIZE],
        len(header_blob),
    ))
    fh.write(header_blob)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def read_header(fh) -> tuple[AmapHeader, int]:
    """Read and parse the header from an open binary file handle.

    Returns ``(AmapHeader, payload_start_offset)`` where *payload_start_offset*
    is the file position immediately after the header blob (start of payload).

    Raises :class:`BadMagicError` or :class:`UnsupportedVersionError` on invalid files.
    """
    raw_prefix = fh.read(_FIXED_PREFIX_SIZE)
    if len(raw_prefix) < _FIXED_PREFIX_SIZE:
        raise BadMagicError("File too short to be a valid .amap archive")

    magic, version, flags, salt, nonce, blob_len = struct.unpack(
        _FIXED_PREFIX_FMT, raw_prefix
    )

    if magic not in (MAGIC, MAGIC_V1):
        raise BadMagicError(
            f"Not an AlphaMap file — magic bytes {magic!r} unrecognised"
        )

    if magic == MAGIC and version > FORMAT_VERSION:
        raise UnsupportedVersionError(
            f"File version {version} > supported {FORMAT_VERSION}. "
            "Upgrade AlphaMap to read this file."
        )

    blob = fh.read(blob_len)
    payload_start = _FIXED_PREFIX_SIZE + blob_len

    if magic == MAGIC_V1:
        # v1 files had a different header format; reconstruct a minimal AmapHeader
        return _parse_v1_header(flags, salt, nonce, blob), payload_start

    obj = json.loads(blob.decode("utf-8"))
    header = AmapHeader(
        version=version,
        flags=flags,
        salt=salt,
        nonce=nonce,
        method=CompressionMethod(obj.get("method", 0)),
        original_size=obj.get("orig_size", 0),
        crc32=obj.get("crc32", 0),
        dict_data=obj.get("dict"),
        filename=obj.get("filename", ""),
        created_at=obj.get("created_at", 0),
    )
    return header, payload_start


def _parse_v1_header(flags: int, salt: bytes, nonce: bytes, blob: bytes) -> AmapHeader:
    """Best-effort parse of a v1 (AM11) header blob for backward compatibility."""
    # v1 blob layout: uint32 dict_len + dict_json_bytes
    dict_data = None
    if len(blob) >= 4:
        dict_len = struct.unpack("<I", blob[:4])[0]
        if dict_len > 0 and len(blob) >= 4 + dict_len:
            try:
                raw = json.loads(blob[4:4 + dict_len].decode("utf-8"))
                dict_data = {"limit": raw.get("limit", 4096), "words": raw.get("words", {})}
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    from ..core.constants import FLAG_ZLIB_FALLBACK
    method = (
        CompressionMethod.ZLIB
        if (flags & FLAG_ZLIB_FALLBACK)
        else CompressionMethod.ALPHAMAP
    )
    return AmapHeader(
        version=1, flags=flags, salt=salt, nonce=nonce,
        method=method, dict_data=dict_data,
    )
