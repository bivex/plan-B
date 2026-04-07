"""Unit tests for domain value objects."""

import pytest

from cryptex.domain.value_objects import Ciphertext, Key, Nonce, Password, Salt


class TestSalt:
    def test_generate_creates_valid_salt(self):
        s = Salt.generate()
        assert len(s.value) == 32

    def test_generate_custom_size(self):
        s = Salt.generate(size=16)
        assert len(s.value) == 16

    def test_rejects_short_salt(self):
        with pytest.raises(ValueError, match="at least 16"):
            Salt(b"short")

    def test_rejects_non_bytes(self):
        with pytest.raises(TypeError):
            Salt("not bytes")  # type: ignore[arg-type]

    def test_immutability(self):
        s = Salt.generate()
        with pytest.raises(AttributeError):
            s.value = b"other"  # type: ignore[misc]


class TestNonce:
    def test_generate_creates_12_bytes(self):
        n = Nonce.generate()
        assert len(n.value) == 12

    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="12 bytes"):
            Nonce(b"wrong")

    def test_accepts_exactly_12(self):
        n = Nonce(b"\x00" * 12)
        assert len(n.value) == 12


class TestKey:
    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            Key(b"short")

    def test_accepts_32_bytes(self):
        k = Key(b"\x00" * 32)
        assert len(k.value) == 32


class TestPassword:
    def test_rejects_short(self):
        with pytest.raises(ValueError, match="8 characters"):
            Password(b"short")

    def test_accepts_valid(self):
        p = Password(b"validpassword")
        assert p.value == b"validpassword"


class TestCiphertext:
    def test_rejects_bad_tag(self):
        with pytest.raises(ValueError, match="16 bytes"):
            Ciphertext(data=b"data", tag=b"short")

    def test_accepts_valid(self):
        ct = Ciphertext(data=b"data", tag=b"\x00" * 16)
        assert ct.data == b"data"
        assert len(ct.tag) == 16
