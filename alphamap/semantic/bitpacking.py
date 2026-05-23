"""
Bit-level read/write utilities for AlphaMap token encoding.

This module is intentionally kept free of AlphaMap-specific logic so it
can be tested and reasoned about independently.  BitWriter and BitReader
are symmetric: whatever BitWriter writes, BitReader reads back identically.

Bit order: MSB-first within each byte.
"""


class BitWriter:
    """Accumulate bits and flush to bytes (MSB-first)."""

    def __init__(self) -> None:
        self.buffer: bytearray = bytearray()
        self.byte: int = 0
        self.bits_in_byte: int = 0

    def write_bits(self, value: int, num_bits: int) -> None:
        """Write the *num_bits* least-significant bits of *value*."""
        for i in range(num_bits - 1, -1, -1):
            bit = (value >> i) & 1
            self.byte = (self.byte << 1) | bit
            self.bits_in_byte += 1
            if self.bits_in_byte == 8:
                self.buffer.append(self.byte)
                self.byte = 0
                self.bits_in_byte = 0

    def flush(self) -> bytes:
        """Pad the last partial byte with zeros and return all bytes.

        The writer is reset after flushing so it can be reused.
        """
        if self.bits_in_byte > 0:
            self.byte <<= 8 - self.bits_in_byte
            self.buffer.append(self.byte)
        result = bytes(self.buffer)
        self.buffer.clear()
        self.byte = 0
        self.bits_in_byte = 0
        return result


class BitReader:
    """Read bits sequentially from a bytes buffer (MSB-first)."""

    def __init__(self, data: bytes) -> None:
        self.data: bytes = data
        self.pos: int = 0
        self.byte: int = 0
        self.bits_in_byte: int = 0

    def read_bits(self, num_bits: int) -> int:
        """Read *num_bits* bits and return them as an integer."""
        result = 0
        for _ in range(num_bits):
            if self.bits_in_byte == 0:
                if self.pos >= len(self.data):
                    raise ValueError("Unexpected end of bit stream")
                self.byte = self.data[self.pos]
                self.pos += 1
                self.bits_in_byte = 8
            result = (result << 1) | ((self.byte >> 7) & 1)
            self.byte = (self.byte << 1) & 0xFF
            self.bits_in_byte -= 1
        return result

    def has_data(self) -> bool:
        """Return True if there are unconsumed bits remaining."""
        return self.pos < len(self.data) or self.bits_in_byte > 0
