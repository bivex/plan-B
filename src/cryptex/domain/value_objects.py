"""Domain value objects — immutable, self-validating data types."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Salt:
    """Random salt for key derivation."""

    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes):
            raise TypeError("Salt must be bytes")
        if len(self.value) < 16:
            raise ValueError("Salt must be at least 16 bytes")

    @classmethod
    def generate(cls, size: int = 32) -> Salt:
        return cls(os.urandom(size))


@dataclass(frozen=True, slots=True)
class Nonce:
    """Random nonce (IV) for AES-GCM — 12 bytes."""

    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes):
            raise TypeError("Nonce must be bytes")
        if len(self.value) != 12:
            raise ValueError("AES-GCM nonce must be exactly 12 bytes")

    @classmethod
    def generate(cls) -> Nonce:
        return cls(os.urandom(12))


@dataclass(frozen=True, slots=True)
class Key:
    """Derived encryption key — 32 bytes for AES-256."""

    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes):
            raise TypeError("Key must be bytes")
        if len(self.value) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")


@dataclass(frozen=True, slots=True)
class Ciphertext:
    """Encrypted data including the GCM authentication tag."""

    data: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("Ciphertext data must be bytes")
        if not isinstance(self.tag, bytes):
            raise TypeError("Tag must be bytes")
        if len(self.tag) != 16:
            raise ValueError("GCM tag must be exactly 16 bytes")


@dataclass(frozen=True, slots=True)
class Password:
    """User-provided password with validation."""

    value: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes):
            raise TypeError("Password must be bytes")
        if len(self.value) < 8:
            raise ValueError("Password must be at least 8 characters")
