"""AlphaMap crypto subpackage — key derivation and integrity checking."""

from .kdf import derive_key
from .integrity import compute_crc32, append_crc32, verify_and_strip_crc32

__all__ = [
    "derive_key",
    "compute_crc32",
    "append_crc32",
    "verify_and_strip_crc32",
]
