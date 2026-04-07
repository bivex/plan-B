"""Tests for uncovered TypeError branches in value objects."""

import pytest

from cryptex.domain.value_objects import Ciphertext, Key, Nonce, Password, Salt


def test_nonce_rejects_non_bytes():
    with pytest.raises(TypeError, match="Nonce must be bytes"):
        Nonce(123)  # type: ignore[arg-type]


def test_key_rejects_non_bytes():
    with pytest.raises(TypeError, match="Key must be bytes"):
        Key("not-bytes")  # type: ignore[arg-type]


def test_ciphertext_data_rejects_non_bytes():
    with pytest.raises(TypeError, match="Ciphertext data must be bytes"):
        Ciphertext(data="not-bytes", tag=b"\x00" * 16)  # type: ignore[arg-type]


def test_ciphertext_tag_rejects_non_bytes():
    with pytest.raises(TypeError, match="Tag must be bytes"):
        Ciphertext(data=b"data", tag=123)  # type: ignore[arg-type]


def test_password_rejects_non_bytes():
    with pytest.raises(TypeError, match="Password must be bytes"):
        Password(123)  # type: ignore[arg-type]
