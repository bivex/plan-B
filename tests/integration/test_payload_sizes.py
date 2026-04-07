"""Tests for encryption/decryption across different payload sizes with padding."""

import struct

import pytest
from pathlib import Path

from cryptex.application.dtos import DecryptRequest, EncryptRequest
from cryptex.application.use_cases.decrypt_file import DecryptFileUseCase
from cryptex.application.use_cases.encrypt_file import EncryptFileUseCase
from cryptex.application.use_cases.padding import PAD_BLOCK, pad, unpad
from cryptex.domain.value_objects import Password
from cryptex.infrastructure.cli.password_provider import PasswordProvider
from cryptex.infrastructure.crypto.aes_gcm_engine import AesGcmEngine
from cryptex.infrastructure.io.file_repository import DiskFileRepository
from cryptex.infrastructure.kdf.scrypt_deriver import ScryptKeyDeriver


class _FixedPw(PasswordProvider):
    def __init__(self, pw: str = "payload-size-test-password"):
        self._pw = pw

    def get_password(self, *, confirm: bool = False) -> Password:
        return Password(self._pw.encode())


HEADER_SIZE = 60  # salt(32) + nonce(12) + tag(16)


def _roundtrip(tmp_path: Path, payload: bytes) -> tuple[bytes, int]:
    """Encrypt payload, decrypt, return (decrypted, encrypted_size)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    src = tmp_path / "payload.bin"
    enc = tmp_path / "payload.bin.enc"
    dec = tmp_path / "payload.bin.dec"

    src.write_bytes(payload)

    pw = _FixedPw()
    crypto = AesGcmEngine()
    deriver = ScryptKeyDeriver()
    files = DiskFileRepository()

    result = EncryptFileUseCase(crypto, deriver, files, pw).execute(
        EncryptRequest(src, enc)
    )
    encrypted_size = result.bytes_written

    DecryptFileUseCase(crypto, deriver, files, pw).execute(
        DecryptRequest(enc, dec)
    )
    return dec.read_bytes(), encrypted_size


# --- Padding unit tests ---


class TestPadding:
    def test_pad_unpad_roundtrip(self):
        original = b"hello world"
        assert unpad(pad(original)) == original

    def test_pad_adds_length_header(self):
        data = b"abc"
        padded = pad(data)
        length = struct.unpack(">Q", padded[:8])[0]
        assert length == 3

    def test_pad_aligns_to_block(self):
        for size in [0, 1, 100, 248, 256, 500, 1000]:
            padded = pad(b"x" * size)
            assert len(padded) % PAD_BLOCK == 0, f"size={size}: padded len {len(padded)} not aligned"

    def test_pad_minimum_one_block_padding(self):
        """Even if payload already aligned — still add 1 block of padding."""
        # 256 - 8(header) = 248 bytes fills exactly one block
        padded = pad(b"x" * 248)
        assert len(padded) == PAD_BLOCK * 2  # 248+8=256 aligned, so +256 padding

    def test_pad_empty(self):
        padded = pad(b"")
        assert len(padded) % PAD_BLOCK == 0
        assert len(padded) >= PAD_BLOCK
        assert unpad(padded) == b""

    def test_unpad_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            unpad(b"\x00" * 7)

    def test_unpad_invalid_length_raises(self):
        # claims 1000 bytes but only has 10
        bad = struct.pack(">Q", 1000) + b"x" * 10
        with pytest.raises(ValueError, match="Invalid length"):
            unpad(bad)

    def test_pad_randomness(self):
        """Two calls produce different padding bytes."""
        p1 = pad(b"test")
        p2 = pad(b"test")
        # length header + plaintext are the same, padding should differ
        assert p1[:12] == p2[:12]  # header + plaintext match
        assert p1 != p2  # but random padding makes total differ


# --- Roundtrip across sizes ---


@pytest.mark.parametrize("size", [
    0,
    1,
    15,
    16,
    17,
    31,
    32,
    33,
    248,   # fills exactly 1 padded block minus header
    256,
    1024,
    4096,
    16 * 1024,
    64 * 1024,
    1024 * 1024,
])
def test_roundtrip_various_sizes(tmp_path: Path, size: int):
    payload = bytes([i % 256 for i in range(size)])
    decrypted, encrypted_size = _roundtrip(tmp_path, payload)
    assert decrypted == payload


# --- Padding hides original size ---


def test_encrypted_size_does_not_reveal_plaintext_length(tmp_path: Path):
    """Different plaintext sizes produce the same encrypted size within a padded block."""
    # 1..200 + 8-byte length header = 9..208, all fit in one 256-byte padded block
    sizes = [1, 10, 50, 100, 200]
    encrypted_sizes = {}
    for size in sizes:
        _, enc_size = _roundtrip(tmp_path / f"s{size}", b"x" * size)
        encrypted_sizes[size] = enc_size

    unique_sizes = set(encrypted_sizes.values())
    assert len(unique_sizes) == 1, (
        f"Expected same encrypted size, got: {encrypted_sizes}"
    )

    # 248 + 8 = 256 exactly fills a block → gets +256 padding, so bigger
    _, enc_248 = _roundtrip(tmp_path / "s248", b"x" * 248)
    assert enc_248 > encrypted_sizes[1]


def test_encrypted_size_is_multiple_of_pad_block(tmp_path: Path):
    """Ciphertext (without file header) is always a multiple of PAD_BLOCK."""
    for size in [0, 1, 100, 248, 256, 500, 4096]:
        _, enc_size = _roundtrip(tmp_path / f"a{size}", b"x" * size)
        ciphertext_len = enc_size - HEADER_SIZE
        assert ciphertext_len % PAD_BLOCK == 0, (
            f"plaintext={size}: ciphertext len {ciphertext_len} not aligned to {PAD_BLOCK}"
        )


def test_all_zeros(tmp_path: Path):
    decrypted, _ = _roundtrip(tmp_path, b"\x00" * 512)
    assert decrypted == b"\x00" * 512


def test_all_0xff(tmp_path: Path):
    decrypted, _ = _roundtrip(tmp_path, b"\xff" * 512)
    assert decrypted == b"\xff" * 512


def test_sequential_bytes(tmp_path: Path):
    payload = bytes(range(256)) * 4
    decrypted, _ = _roundtrip(tmp_path, payload)
    assert decrypted == payload


def test_two_files_same_content_different_ciphertext(tmp_path: Path):
    """Same content encrypted twice produces different files (random salt+nonce+padding)."""
    payload = b"identical content here"
    _, size1 = _roundtrip(tmp_path / "a", payload)
    _, size2 = _roundtrip(tmp_path / "b", payload)

    enc1 = (tmp_path / "a" / "payload.bin.enc").read_bytes()
    enc2 = (tmp_path / "b" / "payload.bin.enc").read_bytes()
    assert enc1 != enc2  # different salt/nonce/padding
