"""Unit tests for encrypt/decrypt use cases with test doubles."""

import os
from pathlib import Path

import pytest

from cryptex.application.dtos import DecryptRequest, EncryptRequest
from cryptex.application.ports.crypto_engine import CryptoEngine
from cryptex.application.ports.file_repository import FileRepository
from cryptex.application.ports.key_deriver import KeyDeriver
from cryptex.application.ports.password_provider import PasswordProvider
from cryptex.application.use_cases.decrypt_file import DecryptFileUseCase
from cryptex.application.use_cases.encrypt_file import EncryptFileUseCase
from cryptex.domain.exceptions import DecryptionError, FileNotFoundError_
from cryptex.domain.value_objects import Ciphertext, Key, Nonce, Password, Salt


# --- Test doubles (in-memory) ---


class FakePasswordProvider(PasswordProvider):
    def __init__(self, password: str = "testpassword123"):
        self._password = password

    def get_password(self, *, confirm: bool = False) -> Password:
        return Password(self._password.encode())


class FakeKeyDeriver(KeyDeriver):
    """Deterministic key deriver for testing."""

    def derive(self, password: Password, salt: Salt) -> Key:
        # Produce a deterministic 32-byte key from password+salt
        import hashlib

        h = hashlib.sha256(password.value + salt.value).digest()
        return Key(h)


class FakeCryptoEngine(CryptoEngine):
    """XOR-based fake cipher for fast unit tests."""

    def encrypt(self, key: Key, nonce: Nonce, plaintext: bytes) -> Ciphertext:
        ct = bytes(a ^ b for a, b in zip(plaintext, key.value[: len(plaintext)]))
        tag = key.value[:16]
        return Ciphertext(data=ct, tag=tag)

    def decrypt(self, key: Key, nonce: Nonce, ciphertext: Ciphertext) -> bytes:
        if ciphertext.tag != key.value[:16]:
            raise DecryptionError("Bad tag")
        pt = bytes(a ^ b for a, b in zip(ciphertext.data, key.value[: len(ciphertext.data)]))
        return pt


class InMemoryFileRepository(FileRepository):
    def __init__(self, files: dict[Path, bytes] | None = None):
        self._files: dict[Path, bytes] = dict(files or {})

    def exists(self, path: Path) -> bool:
        return path in self._files

    def read(self, path: Path) -> bytes:
        if path not in self._files:
            raise FileNotFoundError_(f"Not found: {path}")
        return self._files[path]

    def write(self, path: Path, data: bytes) -> None:
        self._files[path] = data


# --- Tests ---


class TestEncryptFileUseCase:
    def setup_method(self):
        self.passwords = FakePasswordProvider()
        self.deriver = FakeKeyDeriver()
        self.crypto = FakeCryptoEngine()
        self.files = InMemoryFileRepository({Path("test.txt"): b"hello world"})
        self.use_case = EncryptFileUseCase(self.crypto, self.deriver, self.files, self.passwords)

    def test_encrypt_produces_output(self):
        result = self.use_case.execute(EncryptRequest(Path("test.txt"), Path("test.txt.enc")))
        assert result.bytes_written > 0
        assert result.output_path == Path("test.txt.enc")

    def test_encrypt_output_has_header(self):
        self.use_case.execute(EncryptRequest(Path("test.txt"), Path("out.enc")))
        blob = self.files._files[Path("out.enc")]
        # Must be larger than just the file header (60 bytes)
        assert len(blob) > 60

    def test_encrypt_missing_input_raises(self):
        with pytest.raises(FileNotFoundError_):
            self.use_case.execute(EncryptRequest(Path("missing.txt"), Path("out.enc")))


class TestDecryptFileUseCase:
    def setup_method(self):
        self.passwords = FakePasswordProvider()
        self.deriver = FakeKeyDeriver()
        self.crypto = FakeCryptoEngine()
        enc = EncryptFileUseCase(self.crypto, self.deriver, InMemoryFileRepository({Path("t.txt"): b"data"}), self.passwords)
        enc.execute(EncryptRequest(Path("t.txt"), Path("t.txt.enc")))
        self.encrypted_blob = enc._files._files[Path("t.txt.enc")]

        self.files = InMemoryFileRepository({Path("t.txt.enc"): self.encrypted_blob})
        self.use_case = DecryptFileUseCase(self.crypto, self.deriver, self.files, self.passwords)

    def test_decrypt_recovers_plaintext(self):
        result = self.use_case.execute(DecryptRequest(Path("t.txt.enc"), Path("t.txt.dec")))
        assert self.files._files[Path("t.txt.dec")] == b"data"

    def test_decrypt_with_wrong_password_fails(self):
        bad_pw = FakePasswordProvider("wrongpassword99")
        use_case = DecryptFileUseCase(self.crypto, self.deriver, self.files, bad_pw)
        with pytest.raises(DecryptionError):
            use_case.execute(DecryptRequest(Path("t.txt.enc"), Path("out.txt")))

    def test_decrypt_corrupted_data_fails(self):
        self.files._files[Path("bad.enc")] = b"short"
        with pytest.raises(DecryptionError):
            self.use_case.execute(DecryptRequest(Path("bad.enc"), Path("out.txt")))

    def test_decrypt_missing_file_raises(self):
        with pytest.raises(FileNotFoundError_):
            self.use_case.execute(DecryptRequest(Path("missing.enc"), Path("out.txt")))
