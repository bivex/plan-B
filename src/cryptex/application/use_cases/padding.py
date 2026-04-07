"""Padding logic shared between encrypt and decrypt use cases.

Format inside ciphertext:
    original_length (8 bytes, uint64 big-endian) + plaintext + random padding

Padding fills up to the next PAD_BLOCK boundary (256 bytes).
Minimum 1 byte of padding — even empty payloads get padded.
"""

from __future__ import annotations

import os
import struct

_LENGTH_BYTES = 8
PAD_BLOCK = 256


def pad(data: bytes) -> bytes:
    """Prepend length header and add random padding to next block boundary."""
    length_header = struct.pack(">Q", len(data))
    payload = length_header + data
    remainder = len(payload) % PAD_BLOCK
    if remainder == 0:
        pad_len = PAD_BLOCK  # always pad at least 1 block
    else:
        pad_len = PAD_BLOCK - remainder
    return payload + os.urandom(pad_len)


def unpad(data: bytes) -> bytes:
    """Extract original plaintext by reading the length header."""
    if len(data) < _LENGTH_BYTES:
        raise ValueError("Padded data too short to contain length header")
    original_len = struct.unpack(">Q", data[:_LENGTH_BYTES])[0]
    if _LENGTH_BYTES + original_len > len(data):
        raise ValueError("Invalid length in padding header")
    return data[_LENGTH_BYTES : _LENGTH_BYTES + original_len]
