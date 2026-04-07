"""Scrypt key derivation adapter using the cryptography library."""

from __future__ import annotations

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from cryptex.application.ports.key_deriver import KeyDeriver
from cryptex.domain.exceptions import KeyDerivationError
from cryptex.domain.value_objects import Key, Password, Salt


class ScryptKeyDeriver(KeyDeriver):
    """Derives a 32-byte key using scrypt.

    Parameters follow OWASP recommendations:
    n=2^14, r=8, p=1
    """

    def __init__(self, n: int = 2**14, r: int = 8, p: int = 1) -> None:
        self._n = n
        self._r = r
        self._p = p

    def derive(self, password: Password, salt: Salt) -> Key:
        try:
            kdf = Scrypt(
                salt=salt.value,
                length=32,
                n=self._n,
                r=self._r,
                p=self._p,
            )
            key_bytes = kdf.derive(password.value)
            return Key(key_bytes)
        except Exception as exc:
            raise KeyDerivationError(f"Key derivation failed: {exc}") from exc
