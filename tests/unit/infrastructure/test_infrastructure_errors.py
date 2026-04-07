"""Tests for infrastructure error branches."""

import getpass
from pathlib import Path
from unittest.mock import patch

import pytest

from cryptex.domain.exceptions import (
    DecryptionError,
    EncryptionError,
    FileNotFoundError_,
    FileWriteError,
    InvalidPasswordError,
    KeyDerivationError,
)
from cryptex.domain.value_objects import Ciphertext, Key, Nonce, Password, Salt
from cryptex.infrastructure.cli.password_provider import CliPasswordProvider
from cryptex.infrastructure.crypto.aes_gcm_engine import AesGcmEngine
from cryptex.infrastructure.io.file_repository import DiskFileRepository
from cryptex.infrastructure.kdf.scrypt_deriver import ScryptKeyDeriver


class TestAesGcmEngineErrors:
    def test_encrypt_bad_key_length_raises(self):
        """Trigger the except block in encrypt by passing wrong-sized data to internal AESGCM."""
        engine = AesGcmEngine()
        key = Key(b"\x00" * 32)
        nonce = Nonce(b"\x00" * 12)
        # Patch AESGCM.encrypt to raise
        with patch("cryptex.infrastructure.crypto.aes_gcm_engine.AESGCM") as mock:
            mock.side_effect = ValueError("internal error")
            with pytest.raises(EncryptionError, match="AES-GCM encryption failed"):
                engine.encrypt(key, nonce, b"data")


class TestScryptDeriverErrors:
    def test_derive_internal_failure_raises(self):
        deriver = ScryptKeyDeriver()
        pw = Password(b"testpassword123")
        salt = Salt.generate()
        with patch("cryptex.infrastructure.kdf.scrypt_deriver.Scrypt") as mock:
            mock.side_effect = ValueError("internal error")
            with pytest.raises(KeyDerivationError, match="Key derivation failed"):
                deriver.derive(pw, salt)


class TestDiskFileRepositoryErrors:
    def test_read_missing_file_raises(self, tmp_path: Path):
        repo = DiskFileRepository()
        with pytest.raises(FileNotFoundError_, match="not found"):
            repo.read(tmp_path / "nonexistent.txt")

    def test_write_to_invalid_path_raises(self):
        repo = DiskFileRepository()
        # /dev/null/impossible is not writable as a file
        with pytest.raises(FileWriteError, match="Failed to write"):
            repo.write(Path("/dev/null/impossible/path.txt"), b"data")


class TestCliPasswordProvider:
    def test_get_password(self):
        provider = CliPasswordProvider()
        with patch("cryptex.infrastructure.cli.password_provider.getpass") as mock_gp:
            mock_gp.getpass.return_value = "mypassword123"
            pw = provider.get_password(confirm=False)
            assert pw.value == b"mypassword123"

    def test_get_password_with_confirm(self):
        provider = CliPasswordProvider()
        with patch("cryptex.infrastructure.cli.password_provider.getpass") as mock_gp:
            mock_gp.getpass.side_effect = ["mypassword123", "mypassword123"]
            pw = provider.get_password(confirm=True)
            assert pw.value == b"mypassword123"

    def test_empty_password_raises(self):
        provider = CliPasswordProvider()
        with patch("cryptex.infrastructure.cli.password_provider.getpass") as mock_gp:
            mock_gp.getpass.return_value = ""
            with pytest.raises(InvalidPasswordError, match="cannot be empty"):
                provider.get_password()

    def test_passwords_do_not_match_raises(self):
        provider = CliPasswordProvider()
        with patch("cryptex.infrastructure.cli.password_provider.getpass") as mock_gp:
            mock_gp.getpass.side_effect = ["password1", "password2"]
            with pytest.raises(InvalidPasswordError, match="do not match"):
                provider.get_password(confirm=True)
