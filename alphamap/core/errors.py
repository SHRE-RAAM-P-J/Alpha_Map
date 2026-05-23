"""
AlphaMap exception hierarchy.

Raise the most specific subclass you can; callers can catch
AlphaMapError as a blanket filter for all library errors.
"""


class AlphaMapError(Exception):
    """Base class for all AlphaMap errors."""


# ---------------------------------------------------------------------------
# Format / container errors
# ---------------------------------------------------------------------------

class BadMagicError(AlphaMapError):
    """File does not start with the expected magic bytes."""


class UnsupportedVersionError(AlphaMapError):
    """File was written by a newer format version."""


class CorruptionError(AlphaMapError):
    """CRC or authentication tag mismatch — data is corrupted."""


# ---------------------------------------------------------------------------
# Crypto errors
# ---------------------------------------------------------------------------

class DecryptionError(AlphaMapError):
    """AES-GCM tag verification failed (wrong password or corrupted)."""


# ---------------------------------------------------------------------------
# Dictionary / compression errors
# ---------------------------------------------------------------------------

class DictionaryError(AlphaMapError):
    """Dictionary is missing, wrong version, or inconsistent."""


class CompressionError(AlphaMapError):
    """Compression or decompression failed."""


class TokenTooLongError(CompressionError):
    """A single OOV token exceeds MAX_TOKEN_BYTES."""


# ---------------------------------------------------------------------------
# Strategy errors
# ---------------------------------------------------------------------------

class NoStrategyError(AlphaMapError):
    """Strategy selector could not find any usable backend."""
