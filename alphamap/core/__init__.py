"""AlphaMap core — constants, errors, and shared types."""

from .constants import (
    MAGIC,
    MAGIC_V1,
    FORMAT_VERSION,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    KEY_SIZE,
    PBKDF_ROUNDS,
    FLAG_EMBEDDED_DICT,
    FLAG_ZLIB_FALLBACK,
    FLAG_ENCRYPTED,
    DEFAULT_DICT_LIMIT,
    MAX_TOKEN_BYTES,
    MAX_CHUNK_SIZE,
    SAMPLE_BYTES,
    HIGH_ENTROPY_THRESHOLD,
    LOW_ENTROPY_THRESHOLD,
)
from .errors import (
    AlphaMapError,
    BadMagicError,
    UnsupportedVersionError,
    CorruptionError,
    DecryptionError,
    DictionaryError,
    CompressionError,
    TokenTooLongError,
    NoStrategyError,
)
from .types import (
    CompressionMethod,
    FileType,
    FileProfile,
    CompressedPayload,
    BenchmarkResult,
)

__all__ = [
    # constants
    "MAGIC", "MAGIC_V1", "FORMAT_VERSION",
    "SALT_SIZE", "NONCE_SIZE", "TAG_SIZE", "KEY_SIZE", "PBKDF_ROUNDS",
    "FLAG_EMBEDDED_DICT", "FLAG_ZLIB_FALLBACK", "FLAG_ENCRYPTED",
    "DEFAULT_DICT_LIMIT", "MAX_TOKEN_BYTES", "MAX_CHUNK_SIZE",
    "SAMPLE_BYTES", "HIGH_ENTROPY_THRESHOLD", "LOW_ENTROPY_THRESHOLD",
    # errors
    "AlphaMapError", "BadMagicError", "UnsupportedVersionError",
    "CorruptionError", "DecryptionError", "DictionaryError",
    "CompressionError", "TokenTooLongError", "NoStrategyError",
    # types
    "CompressionMethod", "FileType", "FileProfile",
    "CompressedPayload", "BenchmarkResult",
]
