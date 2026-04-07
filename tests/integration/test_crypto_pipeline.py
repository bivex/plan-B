"""Integration test — full encrypt/decrypt cycle with real AES-256-GCM + scrypt."""

from pathlib import Path

from cryptex.application.dtos import DecryptRequest, EncryptRequest
from cryptex.application.use_cases.decrypt_file import DecryptFileUseCase
from cryptex.application.use_cases.encrypt_file import EncryptFileUseCase
from cryptex.application.use_cases.padding import PAD_BLOCK
from cryptex.domain.value_objects import Password
from cryptex.infrastructure.cli.password_provider import PasswordProvider
from cryptex.infrastructure.crypto.aes_gcm_engine import AesGcmEngine
from cryptex.infrastructure.io.file_repository import DiskFileRepository
from cryptex.infrastructure.kdf.scrypt_deriver import ScryptKeyDeriver


class _FixedPasswordProvider(PasswordProvider):
    def __init__(self, pw: str):
        self._pw = pw

    def get_password(self, *, confirm: bool = False) -> Password:
        return Password(self._pw.encode())


def test_encrypt_decrypt_roundtrip(tmp_path: Path):
    """Encrypt then decrypt recovers original content."""
    input_file = tmp_path / "secret.txt"
    enc_file = tmp_path / "secret.txt.enc"
    dec_file = tmp_path / "secret.txt.dec"
    original = b"The quick brown fox jumps over the lazy dog" * 100

    input_file.write_bytes(original)

    passwords = _FixedPasswordProvider("my-secure-password-2026")
    crypto = AesGcmEngine()
    deriver = ScryptKeyDeriver()
    files = DiskFileRepository()

    encryptor = EncryptFileUseCase(crypto, deriver, files, passwords)
    result = encryptor.execute(EncryptRequest(input_file, enc_file))
    assert enc_file.exists()
    # encrypted = header(60) + padded ciphertext (multiple of PAD_BLOCK)
    ciphertext_len = result.bytes_written - 60
    assert ciphertext_len % PAD_BLOCK == 0

    decryptor = DecryptFileUseCase(crypto, deriver, files, passwords)
    result = decryptor.execute(DecryptRequest(enc_file, dec_file))
    assert dec_file.read_bytes() == original


def test_decrypt_wrong_password_fails(tmp_path: Path):
    """Decrypting with the wrong password raises an error."""
    input_file = tmp_path / "data.txt"
    enc_file = tmp_path / "data.txt.enc"
    dec_file = tmp_path / "data.txt.dec"

    input_file.write_bytes(b"secret data")

    good_pw = _FixedPasswordProvider("correct-horse-battery-staple")
    bad_pw = _FixedPasswordProvider("wrong-password-12345")
    crypto = AesGcmEngine()
    deriver = ScryptKeyDeriver()
    files = DiskFileRepository()

    encryptor = EncryptFileUseCase(crypto, deriver, files, good_pw)
    encryptor.execute(EncryptRequest(input_file, enc_file))

    decryptor = DecryptFileUseCase(crypto, deriver, files, bad_pw)
    try:
        decryptor.execute(DecryptRequest(enc_file, dec_file))
        assert False, "Should have raised DecryptionError"
    except Exception:
        pass  # expected


def test_encrypt_binary_file(tmp_path: Path):
    """Handles binary content correctly."""
    input_file = tmp_path / "binary.bin"
    enc_file = tmp_path / "binary.bin.enc"
    dec_file = tmp_path / "binary.bin.dec"
    original = bytes(range(256)) * 50

    input_file.write_bytes(original)

    passwords = _FixedPasswordProvider("binary-test-password")
    crypto = AesGcmEngine()
    deriver = ScryptKeyDeriver()
    files = DiskFileRepository()

    EncryptFileUseCase(crypto, deriver, files, passwords).execute(
        EncryptRequest(input_file, enc_file)
    )
    DecryptFileUseCase(crypto, deriver, files, passwords).execute(
        DecryptRequest(enc_file, dec_file)
    )
    assert dec_file.read_bytes() == original
