"""Domain-level exceptions."""


class CryptoError(Exception):
    """Base exception for encryption/decryption failures."""


class EncryptionError(CryptoError):
    """Failed to encrypt data."""


class DecryptionError(CryptoError):
    """Failed to decrypt data — wrong password or corrupted data."""


class KeyDerivationError(CryptoError):
    """Failed to derive key from password."""


class InvalidPasswordError(CryptoError):
    """Password does not meet requirements."""


class FileNotFoundError_(CryptoError):
    """Input file not found."""


class FileWriteError(CryptoError):
    """Failed to write output file."""
