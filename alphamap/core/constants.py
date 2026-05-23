"""
Protocol constants shared across all AlphaMap subsystems.

Keep this file import-free (stdlib only) so every other module
can import from here without risk of circular dependencies.
"""

# ---------------------------------------------------------------------------
# Container format
# ---------------------------------------------------------------------------

MAGIC: bytes = b"AMAP"          # v2 magic (was b"AM11" in v1)
MAGIC_V1: bytes = b"AM11"       # retained for read-side compatibility
FORMAT_VERSION: int = 2

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

SALT_SIZE: int = 16      # bytes  — PBKDF2 salt
NONCE_SIZE: int = 12     # bytes  — AES-GCM nonce
TAG_SIZE: int = 16       # bytes  — AES-GCM authentication tag
KEY_SIZE: int = 32       # bytes  — AES-256
PBKDF_ROUNDS: int = 200_000

# ---------------------------------------------------------------------------
# Flags byte  (bits 0-7, stored as uint16 in v2)
# ---------------------------------------------------------------------------

FLAG_EMBEDDED_DICT: int = 0x0001   # dictionary is embedded in header
FLAG_ZLIB_FALLBACK: int = 0x0002   # payload is zlib, not AlphaMap tokens
FLAG_ENCRYPTED: int    = 0x0004   # payload is AES-GCM encrypted
FLAG_BROTLI: int       = 0x0008   # payload is brotli (reserved for v0.3)
FLAG_LZMA: int         = 0x0010   # payload is lzma   (reserved for v0.3)

# ---------------------------------------------------------------------------
# Semantic / dictionary
# ---------------------------------------------------------------------------

DEFAULT_DICT_LIMIT: int = 4096          # 12 bits → 4096 word IDs
MAX_TOKEN_BYTES: int = 255              # OOV token length cap
MAX_CHUNK_SIZE: int = 1024 * 1024       # 1 MiB streaming chunk

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

SAMPLE_BYTES: int = 8192    # how many bytes to read for file profiling
HIGH_ENTROPY_THRESHOLD: float = 7.5    # bits/byte — treat as incompressible
LOW_ENTROPY_THRESHOLD: float  = 5.0    # bits/byte — good semantic candidate
