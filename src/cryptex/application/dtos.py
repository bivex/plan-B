"""DTOs for transferring data between layers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class EncryptRequest:
    """Input for the encrypt use case."""

    input_path: Path
    output_path: Path


@dataclass(frozen=True, slots=True)
class DecryptRequest:
    """Input for the decrypt use case."""

    input_path: Path
    output_path: Path


@dataclass(frozen=True, slots=True)
class OperationResult:
    """Output of encrypt/decrypt use case."""

    output_path: Path
    bytes_written: int
