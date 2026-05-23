"""
PBKDF2-HMAC-SHA256 key derivation.

Logic is identical to the original alphamap/crypto.py.
Isolated here so it can be imported by formats/ and pipeline/
without pulling in any compression dependencies.
"""

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from ..core.constants import PBKDF_ROUNDS, KEY_SIZE


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from *password* and *salt*.

    Uses PBKDF2-HMAC-SHA256 with ``PBKDF_ROUNDS`` iterations (200 000).
    The salt must be 16 bytes of cryptographically random data.
    """
    return PBKDF2(
        password,
        salt,
        dkLen=KEY_SIZE,
        count=PBKDF_ROUNDS,
        hmac_hash_module=SHA256,
    )
