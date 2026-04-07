"""Port: abstract interface for obtaining a password from the user."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cryptex.domain.value_objects import Password


class PasswordProvider(ABC):
    """Obtains a password from the user."""

    @abstractmethod
    def get_password(self, *, confirm: bool = False) -> Password:
        ...
