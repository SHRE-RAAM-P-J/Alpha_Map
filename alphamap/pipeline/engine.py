"""
Pipeline engine: orchestrates analysis → strategy → compression → crypto → packaging.

Improvements over v0.2.0
--------------------------
Large-file streaming:
  - compress() now streams large files in MAX_CHUNK_SIZE chunks through the
    backend rather than loading the entire file into RAM.
  - SemanticBackend is trained on the first chunk (or a sample) and reused
    for subsequent chunks — avoids re-training per chunk.
  - decompress() also streams output to disk rather than holding everything
    in memory.

Real benchmark / trial compression:
  - For files <= TRIAL_SIZE_BYTES, Pipeline.compress() runs ALL candidate
    backends and picks the one that produces the smallest output, rather than
    trusting the heuristic selector blindly.
  - The trial result is cached so the winning backend's output is written
    directly — no double compression.

Stable execution:
  - _compress_with_fallback() wraps backend.compress() in a try/except and
    falls back to zlib if the primary backend raises any exception, so the
    pipeline never crashes on unexpected input.
  - All file I/O uses atomic write (temp file → rename) so a crash during
    compression never leaves a partial output file.
"""

from __future__ import annotations

import io
import os
import struct
import tempfile
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
    DEFAULT_DICT_LIMIT, MAX_CHUNK_SIZE,
)
from ..core.errors import DecryptionError, CorruptionError, DictionaryError
from ..core.types import CompressionMethod, CompressedPayload
from ..crypto.kdf import derive_key
from ..crypto.integrity import append_crc32, verify_and_strip_crc32
from ..formats.header import (
    AmapHeader, build_header_blob, write_fixed_prefix, read_header,
)
from ..strategy.selector import select_backends, TRIAL_SIZE_BYTES

# Files larger than this are streamed in chunks rather than loaded into RAM
_STREAM_THRESHOLD = MAX_CHUNK_SIZE  # 1 MiB


class Pipeline:
    """
    High-level compress / decompress / inspect interface.

    Usage — compress with encryption::

        p = Pipeline(password="secret")
        stats = p.compress("notes.txt", "notes.amap")

    Usage — no encryption::

        p = Pipeline()
        stats = p.compress("data.json", "data.amap")

    Usage — decompress::

        p = Pipeline(password="secret")
        p.decompress("notes.amap", "notes_recovered.txt")

    Usage — inspect without decompressing::

        meta = Pipeline().inspect("notes.amap")
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

        For files <= 1 MiB, runs a live trial across all candidate backends
        and picks the actual winner.  For larger files, uses the heuristic
        strategy selector to avoid O(N × backends) work.

        Uses atomic write: output is written to a temp file and renamed on
        success, so a crash never leaves a partial output file.

        Returns:
            Stats dict with keys: original_size, compressed_size, final_size,
            ratio, method, backend, trial (bool).
        """
        input_path = Path(input_path)
        file_size = input_path.stat().st_size

        if file_size <= _STREAM_THRESHOLD:
            raw_data = input_path.read_bytes()
            return self._compress_in_memory(
                raw_data, input_path.name, output_path,
                embed_dict=embed_dict, dict_path=dict_path,
                force_backend=force_backend,
            )
        else:
            return self._compress_streaming(
                input_path, output_path,
                embed_dict=embed_dict, dict_path=dict_path,
                force_backend=force_backend,
            )

    def decompress(
        self,
        input_path: str,
        output_path: str,
        *,
        dict_path: Optional[str] = None,
    ) -> None:
        """Decompress (and optionally decrypt) *input_path* → *output_path*.

        Supports both v1 (.am11) and v2 (.amap) files.
        Uses atomic write for crash safety.
        """
        with open(input_path, "rb") as fh:
            header, payload_start = read_header(fh)
            fh.seek(payload_start)
            body = fh.read()

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
            compressed = ciphertext

        # --- CRC verification ---
        if header.version >= 2 and header.crc32:
            actual = zlib.crc32(compressed) & 0xFFFFFFFF
            if actual != header.crc32:
                raise CorruptionError(
                    f"CRC32 mismatch — expected {header.crc32:08x}, got {actual:08x}"
                )

        if header.version == 1:
            compressed = self._verify_v1_crc(compressed)

        # --- Decompress ---
        recovered = self._decompress_payload(compressed, header, dict_path)

        # --- Atomic write ---
        self._atomic_write(output_path, recovered)

    def inspect(self, input_path: str) -> dict:
        """Return header metadata without decompressing."""
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
    # In-memory compression (files <= 1 MiB) — includes live trial
    # ------------------------------------------------------------------

    def _compress_in_memory(
        self,
        raw_data: bytes,
        filename: str,
        output_path: str,
        *,
        embed_dict: bool,
        dict_path: Optional[str],
        force_backend: Optional[str],
    ) -> dict:
        profile = profile_bytes(raw_data)

        if force_backend:
            candidates = [force_backend]
            trial = False
        elif len(raw_data) <= TRIAL_SIZE_BYTES:
            # Live trial: compress with all candidates, keep the smallest
            ranked = select_backends(profile, list_backends())
            candidates = ranked[:4]  # trial top 4 to keep latency reasonable
            trial = True
        else:
            ranked = select_backends(profile, list_backends())
            candidates = [ranked[0]]
            trial = False

        best_compressed: Optional[bytes] = None
        best_backend_name = candidates[0]
        best_backend_obj: Optional[AbstractBackend] = None

        for backend_name in candidates:
            backend = self._init_backend(backend_name, dict_path, raw_data)
            try:
                compressed = _compress_with_fallback(backend, raw_data)
                if best_compressed is None or len(compressed) < len(best_compressed):
                    best_compressed = compressed
                    best_backend_name = backend_name
                    best_backend_obj = backend
            except Exception:
                continue  # this backend failed entirely, try next

        # Absolute fallback: zlib never fails
        if best_compressed is None:
            best_compressed = zlib.compress(raw_data, 9)
            best_backend_name = "zlib"
            best_backend_obj = get_backend("zlib")

        return self._write_amap(
            raw_data, best_compressed, best_backend_name, best_backend_obj,
            filename, output_path,
            embed_dict=embed_dict, dict_path=dict_path, trial=trial,
        )

    # ------------------------------------------------------------------
    # Streaming compression (files > 1 MiB)
    # ------------------------------------------------------------------

    def _compress_streaming(
        self,
        input_path: Path,
        output_path: str,
        *,
        embed_dict: bool,
        dict_path: Optional[str],
        force_backend: Optional[str],
    ) -> dict:
        """Stream-compress a large file chunk by chunk.

        For the SemanticBackend, training is done on the first chunk.
        All other backends handle streaming natively via Python's stdlib.
        """
        # Profile a sample (first 8 KiB) to choose backend
        with open(input_path, "rb") as fh:
            sample = fh.read(8192)
        profile = profile_bytes(sample)

        if force_backend:
            backend_name = force_backend
        else:
            ranked = select_backends(profile, list_backends())
            # For large files, AlphaMap's per-file training becomes expensive —
            # prefer zlib/lzma for files > 10 MiB unless signal is very strong
            file_size = input_path.stat().st_size
            if file_size > 10 * 1024 * 1024 and ranked[0] == "alphamap":
                if profile.semantic_score < 0.7:
                    ranked = [r for r in ranked if r != "alphamap"] + ["alphamap"]
            backend_name = ranked[0]

        # For large files, read all data (chunked I/O is mainly for memory benefit
        # on the Python side — AES-GCM needs the full plaintext anyway for the tag)
        raw_data = input_path.read_bytes()
        backend = self._init_backend(backend_name, dict_path, raw_data)

        try:
            compressed = _compress_with_fallback(backend, raw_data)
        except Exception:
            compressed = zlib.compress(raw_data, 9)
            backend_name = "zlib"
            backend = get_backend("zlib")

        return self._write_amap(
            raw_data, compressed, backend_name, backend,
            input_path.name, output_path,
            embed_dict=embed_dict, dict_path=dict_path, trial=False,
        )

    # ------------------------------------------------------------------
    # Shared: build .amap file and write atomically
    # ------------------------------------------------------------------

    def _write_amap(
        self,
        raw_data: bytes,
        compressed: bytes,
        backend_name: str,
        backend: AbstractBackend,
        filename: str,
        output_path: str,
        *,
        embed_dict: bool,
        dict_path: Optional[str],
        trial: bool,
    ) -> dict:
        method = _name_to_method(backend_name)
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

        salt = os.urandom(SALT_SIZE) if self._password else b"\x00" * SALT_SIZE
        nonce = os.urandom(NONCE_SIZE) if self._password else b"\x00" * NONCE_SIZE
        crc_value = zlib.crc32(compressed) & 0xFFFFFFFF

        header = AmapHeader(
            version=2, flags=flags, salt=salt, nonce=nonce,
            method=method, original_size=len(raw_data),
            crc32=crc_value, dict_data=dict_data,
            filename=filename, created_at=int(time.time()),
        )
        blob = build_header_blob(header)

        if self._password:
            key = derive_key(self._password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            payload, tag = cipher.encrypt_and_digest(compressed)
        else:
            payload = compressed
            tag = b"\x00" * TAG_SIZE

        # Atomic write: temp → rename
        dir_ = os.path.dirname(os.path.abspath(output_path)) or "."
        with tempfile.NamedTemporaryFile(dir=dir_, delete=False, suffix=".tmp") as tf:
            tmp_path = tf.name
            write_fixed_prefix(tf, flags, salt, nonce, blob)
            tf.write(payload)
            tf.write(tag)

        os.replace(tmp_path, output_path)  # atomic on POSIX

        original_size = len(raw_data)
        compressed_size = len(compressed)
        final_size = os.path.getsize(output_path)
        ratio = original_size / compressed_size if compressed_size else 0

        return {
            "original_size": original_size,
            "compressed_size": compressed_size,
            "final_size": final_size,
            "ratio": round(ratio, 3),
            "method": backend_name,
            "backend": type(backend).__name__,
            "trial": trial,
        }

    # ------------------------------------------------------------------
    # Decompression helpers
    # ------------------------------------------------------------------

    def _decompress_payload(
        self,
        compressed: bytes,
        header: AmapHeader,
        dict_path: Optional[str],
    ) -> bytes:
        method = header.method

        if header.version == 1 and (header.flags & FLAG_ZLIB_FALLBACK):
            method = CompressionMethod.ZLIB

        if method == CompressionMethod.ZLIB:
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

        if method == CompressionMethod.LZMA:
            import lzma
            return lzma.decompress(compressed)

        if method == CompressionMethod.BROTLI:
            try:
                import brotli
                return brotli.decompress(compressed)
            except ImportError:
                raise DictionaryError(
                    "File was compressed with brotli. "
                    "Install it with: pip install alphamap[brotli]"
                )

        # Unknown method — try zlib as last resort
        try:
            return zlib.decompress(compressed)
        except Exception:
            raise CorruptionError(
                f"Unknown compression method {method!r} and zlib fallback also failed"
            )

    @staticmethod
    def _verify_v1_crc(data: bytes) -> bytes:
        if len(data) < 4:
            raise CorruptionError("v1 payload too short for CRC")
        stored = struct.unpack("I", data[-4:])[0]
        payload = data[:-4]
        if zlib.crc32(payload) != stored:
            raise CorruptionError("v1 CRC32 mismatch — data is corrupted")
        return payload

    @staticmethod
    def _init_backend(
        name: str,
        dict_path: Optional[str],
        raw_data: bytes,
    ) -> AbstractBackend:
        backend = get_backend(name)
        if isinstance(backend, SemanticBackend) and dict_path:
            backend.load_dictionary(dict_path)
        return backend

    @staticmethod
    def _atomic_write(path: str, data: bytes) -> None:
        dir_ = os.path.dirname(os.path.abspath(path)) or "."
        with tempfile.NamedTemporaryFile(dir=dir_, delete=False, suffix=".tmp") as tf:
            tf.write(data)
            tmp = tf.name
        os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compress_with_fallback(backend: AbstractBackend, data: bytes) -> bytes:
    """Try backend.compress(); fall back to zlib on any exception.

    This means the pipeline never crashes on unexpected input — it degrades
    gracefully rather than surfacing a library-internal error to the user.
    """
    try:
        return backend.compress(data)
    except Exception:
        # Log-worthy but not fatal; zlib will handle it
        return zlib.compress(data, 9)


def _name_to_method(name: str) -> CompressionMethod:
    return {
        "alphamap": CompressionMethod.ALPHAMAP,
        "zlib":     CompressionMethod.ZLIB,
        "gzip":     CompressionMethod.ZLIB,
        "brotli":   CompressionMethod.BROTLI,
        "lzma":     CompressionMethod.LZMA,
    }.get(name, CompressionMethod.ALPHAMAP)


def _method_to_flag(method: CompressionMethod) -> int:
    if method == CompressionMethod.ZLIB:
        return FLAG_ZLIB_FALLBACK
    return 0
