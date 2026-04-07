"""AES-256-GCM crypto engine adapter using the cryptography library."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptex.application.ports.crypto_engine import CryptoEngine
from cryptex.domain.exceptions import DecryptionError, EncryptionError
from cryptex.domain.value_objects import Ciphertext, Key, Nonce


class AesGcmEngine(CryptoEngine):
    """Encrypts/decrypts using AES-256-GCM via the cryptography library."""

    def encrypt(self, key: Key, nonce: Nonce, plaintext: bytes) -> Ciphertext:
        try:
            aesgcm = AESGCM(key.value)
            # AESGCM.encrypt returns ciphertext+tag concatenated
            ct_and_tag = aesgcm.encrypt(nonce.value, plaintext, None)
            # Tag is the last 16 bytes
            tag = ct_and_tag[-16:]
            ct = ct_and_tag[:-16]
            return Ciphertext(data=ct, tag=tag)
        except Exception as exc:
            raise EncryptionError(f"AES-GCM encryption failed: {exc}") from exc

    def decrypt(self, key: Key, nonce: Nonce, ciphertext: Ciphertext) -> bytes:
        try:
            aesgcm = AESGCM(key.value)
            # Reconstruct ciphertext+tag format expected by AESGCM
            ct_and_tag = ciphertext.data + ciphertext.tag
            return aesgcm.decrypt(nonce.value, ct_and_tag, None)
        except Exception as exc:
            raise DecryptionError(
                "Decryption failed — wrong password or corrupted data"
            ) from exc
