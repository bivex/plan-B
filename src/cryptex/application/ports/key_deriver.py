"""Port: abstract interface for key derivation from password."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cryptex.domain.value_objects import Key, Password, Salt


class KeyDeriver(ABC):
    """Derives an encryption key from a password and salt using a KDF."""

    @abstractmethod
    def derive(self, password: Password, salt: Salt) -> Key:
        ...
