"""Decrypt file use case — reverses the encrypt operation."""

from __future__ import annotations

from cryptex.application.dtos import DecryptRequest, OperationResult
from cryptex.application.ports.crypto_engine import CryptoEngine
from cryptex.application.ports.file_repository import FileRepository
from cryptex.application.ports.key_deriver import KeyDeriver
from cryptex.application.ports.password_provider import PasswordProvider
from cryptex.application.use_cases.padding import unpad
from cryptex.domain.exceptions import DecryptionError, FileNotFoundError_
from cryptex.domain.value_objects import Ciphertext, Key, Nonce, Salt

_SALT_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_HEADER_LEN = _SALT_LEN + _NONCE_LEN + _TAG_LEN


class DecryptFileUseCase:
    """Decrypts a file encrypted by EncryptFileUseCase."""

    def __init__(
        self,
        crypto: CryptoEngine,
        deriver: KeyDeriver,
        files: FileRepository,
        passwords: PasswordProvider,
    ) -> None:
        self._crypto = crypto
        self._deriver = deriver
        self._files = files
        self._passwords = passwords

    def execute(self, request: DecryptRequest) -> OperationResult:
        if not self._files.exists(request.input_path):
            raise FileNotFoundError_(f"Input file not found: {request.input_path}")

        try:
            blob = self._files.read(request.input_path)
            if len(blob) < _HEADER_LEN:
                raise DecryptionError("File too small to be a valid encrypted file")

            salt = Salt(blob[:_SALT_LEN])
            nonce = Nonce(blob[_SALT_LEN : _SALT_LEN + _NONCE_LEN])
            tag = blob[_SALT_LEN + _NONCE_LEN : _HEADER_LEN]
            ciphertext_data = blob[_HEADER_LEN:]

            password = self._passwords.get_password(confirm=False)
            key = self._deriver.derive(password, salt)

            ciphertext = Ciphertext(data=ciphertext_data, tag=tag)
            padded = self._crypto.decrypt(key, nonce, ciphertext)
            plaintext = unpad(padded)

            self._files.write(request.output_path, plaintext)

            return OperationResult(
                output_path=request.output_path,
                bytes_written=len(plaintext),
            )
        except DecryptionError:
            raise
        except FileNotFoundError_:
            raise
        except Exception as exc:
            raise DecryptionError(f"Decryption failed: {exc}") from exc
