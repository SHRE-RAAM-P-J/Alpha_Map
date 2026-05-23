"""Tests for alphamap.crypto — key derivation and CRC32 integrity."""

import os
import struct
import zlib
import pytest

from alphamap.crypto.kdf import derive_key
from alphamap.crypto.integrity import (
    compute_crc32,
    append_crc32,
    verify_and_strip_crc32,
)
from alphamap.core.errors import CorruptionError
from alphamap.core.constants import KEY_SIZE, SALT_SIZE


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def test_derive_key_length():
    salt = os.urandom(SALT_SIZE)
    key = derive_key("hunter2", salt)
    assert len(key) == KEY_SIZE  # 32 bytes for AES-256


def test_derive_key_deterministic():
    salt = b"\x00" * SALT_SIZE
    key1 = derive_key("password", salt)
    key2 = derive_key("password", salt)
    assert key1 == key2


def test_derive_key_different_passwords():
    salt = b"\x00" * SALT_SIZE
    assert derive_key("pass1", salt) != derive_key("pass2", salt)


def test_derive_key_different_salts():
    key1 = derive_key("password", b"\x00" * SALT_SIZE)
    key2 = derive_key("password", b"\x01" * SALT_SIZE)
    assert key1 != key2


# ---------------------------------------------------------------------------
# CRC32 integrity
# ---------------------------------------------------------------------------

def test_compute_crc32_is_4_bytes():
    result = compute_crc32(b"hello world")
    assert len(result) == 4


def test_compute_crc32_deterministic():
    assert compute_crc32(b"test") == compute_crc32(b"test")


def test_compute_crc32_different_inputs():
    assert compute_crc32(b"hello") != compute_crc32(b"world")


def test_compute_crc32_matches_stdlib():
    data = b"alphamap test data"
    expected = struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)
    assert compute_crc32(data) == expected


def test_append_and_verify_roundtrip():
    data = b"some compressed payload here"
    with_crc = append_crc32(data)
    assert len(with_crc) == len(data) + 4
    recovered = verify_and_strip_crc32(with_crc)
    assert recovered == data


def test_verify_detects_corruption():
    data = b"some payload"
    with_crc = append_crc32(data)
    corrupted = bytearray(with_crc)
    corrupted[3] ^= 0xFF   # flip bits in payload
    with pytest.raises(CorruptionError):
        verify_and_strip_crc32(bytes(corrupted))


def test_verify_detects_crc_tamper():
    data = b"some payload"
    with_crc = bytearray(append_crc32(data))
    with_crc[-1] ^= 0x01   # flip a bit in the CRC itself
    with pytest.raises(CorruptionError):
        verify_and_strip_crc32(bytes(with_crc))


def test_verify_too_short():
    with pytest.raises(CorruptionError):
        verify_and_strip_crc32(b"\x00\x00\x00")


def test_append_crc32_empty():
    with_crc = append_crc32(b"")
    recovered = verify_and_strip_crc32(with_crc)
    assert recovered == b""
