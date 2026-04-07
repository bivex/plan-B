"""Encrypt file use case — orchestrates key derivation, encryption, and file output."""

from __future__ import annotations

from cryptex.application.dtos import EncryptRequest, OperationResult
from cryptex.application.ports.crypto_engine import CryptoEngine
from cryptex.application.ports.file_repository import FileRepository
from cryptex.application.ports.key_deriver import KeyDeriver
from cryptex.application.ports.password_provider import PasswordProvider
from cryptex.application.use_cases.padding import pad
from cryptex.domain.exceptions import EncryptionError, FileNotFoundError_
from cryptex.domain.value_objects import Nonce, Salt

_SALT_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16


class EncryptFileUseCase:
    """Encrypts a file with AES-256-GCM using a password-derived key.

    Output file format: salt | nonce | tag | ciphertext(padded)
    """

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

    def execute(self, request: EncryptRequest) -> OperationResult:
        if not self._files.exists(request.input_path):
            raise FileNotFoundError_(f"Input file not found: {request.input_path}")

        try:
            password = self._passwords.get_password(confirm=True)
            salt = Salt.generate(size=_SALT_LEN)
            nonce = Nonce.generate()
            key = self._deriver.derive(password, salt)

            plaintext = self._files.read(request.input_path)
            padded = pad(plaintext)
            ciphertext = self._crypto.encrypt(key, nonce, padded)

            blob = salt.value + nonce.value + ciphertext.tag + ciphertext.data
            self._files.write(request.output_path, blob)

            return OperationResult(
                output_path=request.output_path,
                bytes_written=len(blob),
            )
        except (EncryptionError, FileNotFoundError_):
            raise
        except Exception as exc:
            raise EncryptionError(f"Encryption failed: {exc}") from exc
