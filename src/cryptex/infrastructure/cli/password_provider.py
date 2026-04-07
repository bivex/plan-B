"""CLI password provider — reads password from terminal with getpass."""

from __future__ import annotations

import getpass

from cryptex.application.ports.password_provider import PasswordProvider
from cryptex.domain.exceptions import InvalidPasswordError
from cryptex.domain.value_objects import Password


class CliPasswordProvider(PasswordProvider):
    """Prompts the user for a password on the terminal."""

    def get_password(self, *, confirm: bool = False) -> Password:
        pw = getpass.getpass("Enter password: ")
        if not pw:
            raise InvalidPasswordError("Password cannot be empty")

        if confirm:
            pw2 = getpass.getpass("Confirm password: ")
            if pw != pw2:
                raise InvalidPasswordError("Passwords do not match")

        return Password(pw.encode("utf-8"))
