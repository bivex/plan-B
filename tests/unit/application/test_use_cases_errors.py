"""Tests for catch-all exception handlers in encrypt/decrypt use cases."""

from pathlib import Path

import pytest

from cryptex.application.dtos import DecryptRequest, EncryptRequest
from cryptex.application.ports.crypto_engine import CryptoEngine
from cryptex.application.ports.file_repository import FileRepository
from cryptex.application.ports.key_deriver import KeyDeriver
from cryptex.application.ports.password_provider import PasswordProvider
from cryptex.application.use_cases.decrypt_file import DecryptFileUseCase
from cryptex.application.use_cases.encrypt_file import EncryptFileUseCase
from cryptex.domain.exceptions import DecryptionError, EncryptionError
from cryptex.domain.value_objects import Ciphertext, Key, Nonce, Password, Salt


class _Pw(PasswordProvider):
    def get_password(self, *, confirm=False):
        return Password(b"testpassword123")


class _Deriver(KeyDeriver):
    def derive(self, password, salt):
        import hashlib
        return Key(hashlib.sha256(password.value + salt.value).digest())


class _Files(FileRepository):
    def __init__(self):
        self._data = {Path("in.txt"): b"data"}

    def exists(self, path):
        return path in self._data

    def read(self, path):
        return self._data[path]

    def write(self, path, data):
        self._data[path] = data


class _BoomCrypto(CryptoEngine):
    """Crypto that always raises a non-domain exception."""

    def encrypt(self, key, nonce, plaintext):
        raise RuntimeError("unexpected boom")

    def decrypt(self, key, nonce, ciphertext):
        raise RuntimeError("unexpected boom")


class TestEncryptCatchAll:
    def test_unexpected_exception_wrapped(self):
        uc = EncryptFileUseCase(_BoomCrypto(), _Deriver(), _Files(), _Pw())
        with pytest.raises(EncryptionError, match="Encryption failed"):
            uc.execute(EncryptRequest(Path("in.txt"), Path("out.enc")))


class TestDecryptCatchAll:
    def test_unexpected_exception_wrapped(self):
        # Need a valid encrypted blob for decrypt to get past file reads
        files = _Files()
        files._data[Path("enc.enc")] = (
            b"\x00" * 32 +  # salt
            b"\x00" * 12 +  # nonce
            b"\x00" * 16 +  # tag
            b"\x00" * 32    # ciphertext
        )
        uc = DecryptFileUseCase(_BoomCrypto(), _Deriver(), files, _Pw())
        with pytest.raises(DecryptionError, match="Decryption failed"):
            uc.execute(DecryptRequest(Path("enc.enc"), Path("out.txt")))
