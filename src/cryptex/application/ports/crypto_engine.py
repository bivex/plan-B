"""Port: abstract interface for encryption/decryption."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cryptex.domain.value_objects import Ciphertext, Key, Nonce


class CryptoEngine(ABC):
    """Encrypts and decrypts bytes using an AEAD cipher."""

    @abstractmethod
    def encrypt(self, key: Key, nonce: Nonce, plaintext: bytes) -> Ciphertext:
        ...

    @abstractmethod
    def decrypt(self, key: Key, nonce: Nonce, ciphertext: Ciphertext) -> bytes:
        ...
