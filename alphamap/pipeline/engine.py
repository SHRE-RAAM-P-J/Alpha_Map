"""
Pipeline engine: orchestrates analysis → strategy → compression → crypto → packaging.

This is the single entry point for all compress/decompress operations.
It replaces the monolithic AlphaMapStream from v1 while preserving
all existing behaviour (AES-GCM, PBKDF2, embedded dict, zlib fallback).

Differences from v1 AlphaMapStream:
    - Strategy is selected automatically from FileProfile (not hardcoded to semantic+zlib).
    - Dict embed/no-embed is still supported.
    - Crypto is optional (no password → no encryption, FLAG_ENCRYPTED not set).
    - Output format is .amap v2 (reads v1 .am11 files for backward compat).
    - print() calls replaced by structured stats dict returned from compress().
"""

from __future__ import annotations

import io
import os
import struct
import time
import zlib
from pathlib import Path
from typing import Optional

from Crypto.Cipher import AES

from ..analysis.profiler import profile_file, profile_bytes
from ..backends import get_backend, list_backends, SemanticBackend
from ..backends.base import AbstractBackend
from ..core.constants import (
    SALT_SIZE, NONCE_SIZE, TAG_SIZE,
    FLAG_EMBEDDED_DICT, FLAG_ENCRYPTED, FLAG_ZLIB_FALLBACK,
    DEFAULT_DICT_LIMIT,
)
from ..core.errors import DecryptionError, CorruptionError, DictionaryError
from ..core.types import CompressionMethod, CompressedPayload
from ..crypto.kdf import derive_key
from ..crypto.integrity import append_crc32, verify_and_strip_crc32
from ..formats.header import (
    AmapHeader, build_header_blob, write_fixed_prefix, read_header,
)
from ..strategy.selector import select_backends


class Pipeline:
    """
    High-level compress / decompress / inspect interface.

    Usage — compress a text file with encryption::

        p = Pipeline(password="secret")
        stats = p.compress("notes.txt", "notes.amap")

    Usage — no encryption::

        p = Pipeline()
        stats = p.compress("data.json", "data.amap")

    Usage — decompress::

        p = Pipeline(password="secret")
        p.decompress("notes.amap", "notes_recovered.txt")
    """

    def __init__(
        self,
        password: Optional[str] = None,
        dict_limit: int = DEFAULT_DICT_LIMIT,
    ) -> None:
        self._password = password
        self._dict_limit = dict_limit

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compress(
        self,
        input_path: str,
        output_path: str,
        *,
        embed_dict: bool = True,
        dict_path: Optional[str] = None,
        force_backend: Optional[str] = None,
    ) -> dict:
        """Compress (and optionally encrypt) *input_path* → *output_path*.

        Args:
            input_path:    Source file.
            output_path:   Destination .amap file.
            embed_dict:    Embed the semantic dictionary in the header.
            dict_path:     Path to an external pre-trained dictionary.
            force_backend: Override automatic strategy with a specific backend name.

        Returns:
            Stats dict with keys: original_size, compressed_size, final_size,
            ratio, method, backend.
        """
        input_path = Path(input_path)
        raw_data = input_path.read_bytes()
        original_size = len(raw_data)

        # --- 1. Analyse ---
        profile = profile_bytes(raw_data)

        # --- 2. Select backend ---
        if force_backend:
            backend_name = force_backend
        else:
            ranked = select_backends(profile, list_backends())
            backend_name = ranked[0]

        # --- 3. Initialise backend (special handling for semantic) ---
        backend = self._init_backend(backend_name, dict_path, raw_data)

        # --- 4. Compress ---
        compressed = backend.compress(raw_data)
        method = _name_to_method(backend_name)

        # --- 5. Build flags ---
        flags = _method_to_flag(method)
        dict_data = None
        if isinstance(backend, SemanticBackend) and embed_dict and not dict_path:
            flags |= FLAG_EMBEDDED_DICT
            dict_data = {
                "limit": backend.dict_limit,
                "words": backend.word_to_id,
            }

        if self._password:
            flags |= FLAG_ENCRYPTED

        # --- 6. Build header blob ---
        salt = os.urandom(SALT_SIZE) if self._password else b"\x00" * SALT_SIZE
        nonce = os.urandom(NONCE_SIZE) if self._password else b"\x00" * NONCE_SIZE

        crc_payload = compressed  # CRC over compressed plaintext
        crc_value = zlib.crc32(crc_payload) & 0xFFFFFFFF

        header = AmapHeader(
            version=2,
            flags=flags,
            salt=salt,
            nonce=nonce,
            method=method,
            original_size=original_size,
            crc32=crc_value,
            dict_data=dict_data,
            filename=input_path.name,
            created_at=int(time.time()),
        )
        blob = build_header_blob(header)

        # --- 7. Encrypt payload if password supplied ---
        if self._password:
            key = derive_key(self._password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            payload, tag = cipher.encrypt_and_digest(compressed)
        else:
            payload = compressed
            tag = b"\x00" * TAG_SIZE

        # --- 8. Write .amap file ---
        with open(output_path, "wb") as fh:
            write_fixed_prefix(fh, flags, salt, nonce, blob)
            fh.write(payload)
            fh.write(tag)

        final_size = os.path.getsize(output_path)
        ratio = original_size / compressed_len if (compressed_len := len(compressed)) else 0
        return {
            "original_size": original_size,
            "compressed_size": len(compressed),
            "final_size": final_size,
            "ratio": round(ratio, 3),
            "method": backend_name,
            "backend": type(backend).__name__,
        }

    def decompress(
        self,
        input_path: str,
        output_path: str,
        *,
        dict_path: Optional[str] = None,
    ) -> None:
        """Decompress (and optionally decrypt) *input_path* → *output_path*.

        Supports both v1 (.am11) and v2 (.amap) files.
        """
        with open(input_path, "rb") as fh:
            header, payload_start = read_header(fh)
            fh.seek(payload_start)
            body = fh.read()

        # Split TAG off the end
        ciphertext, tag = body[:-TAG_SIZE], body[-TAG_SIZE:]

        # --- Decrypt ---
        if header.is_encrypted:
            if not self._password:
                raise DecryptionError("File is encrypted — provide a password")
            key = derive_key(self._password, header.salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=header.nonce)
            try:
                compressed = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError as exc:
                raise DecryptionError(
                    "Decryption failed — wrong password or corrupted file"
                ) from exc
        else:
            compressed = ciphertext  # tag is ignored (all zeros)

        # --- Verify CRC (v2 only) ---
        if header.version >= 2 and header.crc32:
            actual = zlib.crc32(compressed) & 0xFFFFFFFF
            if actual != header.crc32:
                raise CorruptionError(
                    f"CRC32 mismatch — expected {header.crc32:08x}, got {actual:08x}"
                )

        # --- Legacy CRC (v1 format stored CRC at the end of plaintext) ---
        if header.version == 1:
            compressed = self._verify_v1_crc(compressed)

        # --- Decompress ---
        recovered = self._decompress_payload(compressed, header, dict_path)

        Path(output_path).write_bytes(recovered)

    def inspect(self, input_path: str) -> dict:
        """Return a dict of header metadata without decompressing."""
        with open(input_path, "rb") as fh:
            header, _ = read_header(fh)
        return {
            "version": header.version,
            "method": header.method.name,
            "original_size": header.original_size,
            "encrypted": header.is_encrypted,
            "embedded_dict": header.has_embedded_dict,
            "filename": header.filename,
            "created_at": header.created_at,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_backend(
        self,
        name: str,
        dict_path: Optional[str],
        raw_data: bytes,
    ) -> AbstractBackend:
        backend = get_backend(name)
        if isinstance(backend, SemanticBackend):
            if dict_path:
                backend.load_dictionary(dict_path)
            # Training happens inside SemanticBackend.compress()
        return backend

    def _decompress_payload(
        self,
        compressed: bytes,
        header: AmapHeader,
        dict_path: Optional[str],
    ) -> bytes:
        method = header.method

        # v1 flag compat: FLAG_ZLIB_FALLBACK was bit 1
        if header.version == 1 and (header.flags & FLAG_ZLIB_FALLBACK):
            method = CompressionMethod.ZLIB

        if method == CompressionMethod.ZLIB:
            # Both zlib and gzip backends map to ZLIB method.
            # Detect by magic bytes: gzip starts with \x1f\x8b.
            if compressed[:2] == b"\x1f\x8b":
                import gzip as _gzip
                return _gzip.decompress(compressed)
            return zlib.decompress(compressed)

        if method == CompressionMethod.ALPHAMAP:
            from ..backends.semantic_backend import SemanticBackend as SB
            backend = SB(dict_limit=self._dict_limit)
            if header.dict_data:
                backend.set_word_map(
                    header.dict_data["words"],
                    header.dict_data.get("limit", self._dict_limit),
                )
            elif dict_path:
                backend.load_dictionary(dict_path)
            else:
                raise DictionaryError(
                    "No dictionary embedded or provided — "
                    "pass dict_path or re-compress with embed_dict=True"
                )
            return backend.decompress(compressed)

        # Brotli / lzma (future)
        backend = get_backend(method.name.lower())
        return backend.decompress(compressed)

    @staticmethod
    def _verify_v1_crc(data: bytes) -> bytes:
        """v1 stored CRC32 as the last 4 bytes of the plaintext (struct.pack 'I', native endian)."""
        if len(data) < 4:
            raise CorruptionError("v1 payload too short for CRC")
        stored = struct.unpack("I", data[-4:])[0]
        payload = data[:-4]
        if zlib.crc32(payload) != stored:
            raise CorruptionError("v1 CRC32 mismatch — data is corrupted")
        return payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _name_to_method(name: str) -> CompressionMethod:
    _MAP = {
        "alphamap": CompressionMethod.ALPHAMAP,
        "zlib":     CompressionMethod.ZLIB,
        "gzip":     CompressionMethod.ZLIB,   # gzip and zlib share the flag for now
        "brotli":   CompressionMethod.BROTLI,
        "lzma":     CompressionMethod.LZMA,
    }
    return _MAP.get(name, CompressionMethod.ALPHAMAP)


def _method_to_flag(method: CompressionMethod) -> int:
    if method == CompressionMethod.ZLIB:
        return FLAG_ZLIB_FALLBACK
    return 0  # ALPHAMAP = no extra flag
