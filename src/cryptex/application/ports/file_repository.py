"""Port: abstract interface for file I/O."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class FileRepository(ABC):
    """Reads and writes file contents."""

    @abstractmethod
    def exists(self, path: Path) -> bool:
        ...

    @abstractmethod
    def read(self, path: Path) -> bytes:
        ...

    @abstractmethod
    def write(self, path: Path, data: bytes) -> None:
        ...
