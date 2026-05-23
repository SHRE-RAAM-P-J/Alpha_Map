"""
Integrity verification helpers.

CRC32 is used to detect silent corruption of the *plaintext* data before
compression and after decompression.  It is stored inside the AES-GCM
authenticated envelope, so it is tamper-evident (anyone modifying the
ciphertext will break the GCM tag before the CRC even runs).

The CRC exists as a second line of defence for detecting bugs in our own
encode/decode logic, not as a security primitive.
"""

import struct
import zlib

from ..core.errors import CorruptionError


def compute_crc32(data: bytes) -> bytes:
    """Return the CRC32 of *data* packed as a 4-byte little-endian uint32."""
    return struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)


def append_crc32(data: bytes) -> bytes:
    """Return *data* with its CRC32 appended (4 bytes)."""
    return data + compute_crc32(data)


def verify_and_strip_crc32(data: bytes) -> bytes:
    """Verify the trailing 4-byte CRC32 and return the payload without it.

    Raises :class:`~alphamap.core.errors.CorruptionError` on mismatch.
    """
    if len(data) < 4:
        raise CorruptionError("Data too short to contain a CRC32 trailer")
    payload, stored_crc = data[:-4], data[-4:]
    expected_crc = compute_crc32(payload)
    if stored_crc != expected_crc:
        raise CorruptionError("CRC32 mismatch — data is corrupted")
    return payload
