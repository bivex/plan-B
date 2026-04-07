"""File I/O adapter — reads and writes raw bytes from/to disk."""

from __future__ import annotations

from pathlib import Path

from cryptex.application.ports.file_repository import FileRepository
from cryptex.domain.exceptions import FileNotFoundError_, FileWriteError


class DiskFileRepository(FileRepository):
    """Reads and writes files on the local filesystem."""

    def exists(self, path: Path) -> bool:
        return path.exists()

    def read(self, path: Path) -> bytes:
        if not path.exists():
            raise FileNotFoundError_(f"File not found: {path}")
        return path.read_bytes()

    def write(self, path: Path, data: bytes) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except OSError as exc:
            raise FileWriteError(f"Failed to write {path}: {exc}") from exc
