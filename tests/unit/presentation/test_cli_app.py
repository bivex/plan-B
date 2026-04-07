"""Tests for CLI app entry point."""

from pathlib import Path
from unittest.mock import patch

import pytest

from cryptex.presentation.cli.app import main


def _make_container(tmp_path):
    """Build real container with fixed password for CLI tests."""
    from cryptex.domain.value_objects import Password
    from cryptex.infrastructure.cli.password_provider import PasswordProvider
    from cryptex.infrastructure.crypto.aes_gcm_engine import AesGcmEngine
    from cryptex.infrastructure.io.file_repository import DiskFileRepository
    from cryptex.infrastructure.kdf.scrypt_deriver import ScryptKeyDeriver

    class _Pw(PasswordProvider):
        def get_password(self, *, confirm=False):
            return Password(b"cli-test-password")

    return AesGcmEngine(), ScryptKeyDeriver(), DiskFileRepository(), _Pw()


class TestCliEncrypt:
    def test_encrypt(self, tmp_path):
        src = tmp_path / "test.txt"
        src.write_text("hello world")
        out = tmp_path / "test.txt.enc"

        with patch(
            "cryptex.presentation.cli.app._build_container",
            return_value=_make_container(tmp_path),
        ):
            ret = main(["encrypt", str(src), "-o", str(out)])
        assert ret == 0
        assert out.exists()

    def test_encrypt_missing_file(self, tmp_path):
        with patch(
            "cryptex.presentation.cli.app._build_container",
            return_value=_make_container(tmp_path),
        ):
            ret = main(["encrypt", str(tmp_path / "nonexistent.txt")])
        assert ret == 1


class TestCliDecrypt:
    def test_decrypt(self, tmp_path):
        from cryptex.application.dtos import EncryptRequest
        from cryptex.application.use_cases.encrypt_file import EncryptFileUseCase
        from cryptex.domain.value_objects import Password
        from cryptex.infrastructure.cli.password_provider import PasswordProvider
        from cryptex.infrastructure.crypto.aes_gcm_engine import AesGcmEngine
        from cryptex.infrastructure.io.file_repository import DiskFileRepository
        from cryptex.infrastructure.kdf.scrypt_deriver import ScryptKeyDeriver

        class _Pw(PasswordProvider):
            def get_password(self, *, confirm=False):
                return Password(b"cli-test-password")

        src = tmp_path / "test.txt"
        enc = tmp_path / "test.txt.enc"
        dec = tmp_path / "result.txt"
        src.write_text("secret data")

        pw = _Pw()
        crypto = AesGcmEngine()
        deriver = ScryptKeyDeriver()
        files = DiskFileRepository()

        EncryptFileUseCase(crypto, deriver, files, pw).execute(
            EncryptRequest(src, enc)
        )

        with patch(
            "cryptex.presentation.cli.app._build_container",
            return_value=(crypto, deriver, files, pw),
        ):
            ret = main(["decrypt", str(enc), "-o", str(dec)])
        assert ret == 0
        assert dec.read_text() == "secret data"


class TestCliDefaults:
    def test_default_output_encrypt(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_text("content")
        expected_out = tmp_path / "data.txt.enc"

        with patch(
            "cryptex.presentation.cli.app._build_container",
            return_value=_make_container(tmp_path),
        ):
            ret = main(["encrypt", str(src)])
        assert ret == 0
        assert expected_out.exists()

    def test_no_command_shows_error(self):
        ret = main([])
        assert ret == 1

    def test_real_build_container_encrypt(self, tmp_path):
        """Test with real _build_container (exercises lines 21-26) by mocking getpass."""
        src = tmp_path / "real.txt"
        src.write_text("testing real container")

        with patch("cryptex.infrastructure.cli.password_provider.getpass") as mock_gp:
            mock_gp.getpass.return_value = "real-container-pw"
            ret = main(["encrypt", str(src)])
        assert ret == 0
        assert (tmp_path / "real.txt.enc").exists()

    def test_real_build_container_decrypt_error(self, tmp_path):
        """Decrypt a corrupted file with real container to hit CryptoError catch (lines 72-73)."""
        bad_enc = tmp_path / "bad.enc"
        bad_enc.write_bytes(b"\x00" * 100)

        with patch("cryptex.infrastructure.cli.password_provider.getpass") as mock_gp:
            mock_gp.getpass.return_value = "some-password-123"
            ret = main(["decrypt", str(bad_enc)])
        assert ret == 1
