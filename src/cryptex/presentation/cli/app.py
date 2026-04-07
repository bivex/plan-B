"""CLI entry point for cryptex — wires dependencies and parses arguments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptex.application.dtos import DecryptRequest, EncryptRequest
from cryptex.application.ports.crypto_engine import CryptoEngine
from cryptex.application.ports.file_repository import FileRepository
from cryptex.application.ports.key_deriver import KeyDeriver
from cryptex.application.ports.password_provider import PasswordProvider
from cryptex.application.use_cases.decrypt_file import DecryptFileUseCase
from cryptex.application.use_cases.encrypt_file import EncryptFileUseCase
from cryptex.domain.exceptions import CryptoError


def _build_container() -> tuple[CryptoEngine, KeyDeriver, FileRepository, PasswordProvider]:
    """Compose the dependency graph — single place for wiring."""
    from cryptex.infrastructure.cli.password_provider import CliPasswordProvider
    from cryptex.infrastructure.crypto.aes_gcm_engine import AesGcmEngine
    from cryptex.infrastructure.io.file_repository import DiskFileRepository
    from cryptex.infrastructure.kdf.scrypt_deriver import ScryptKeyDeriver

    return AesGcmEngine(), ScryptKeyDeriver(), DiskFileRepository(), CliPasswordProvider()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cryptex",
        description="Encrypt/decrypt files with AES-256-GCM + scrypt",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", type=Path, help="Input file path")
    enc.add_argument("-o", "--output", type=Path, help="Output file path (default: <input>.enc)")

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input", type=Path, help="Encrypted file path")
    dec.add_argument("-o", "--output", type=Path, help="Output file path (default: <input>.dec.txt)")

    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 1
    crypto, deriver, files, passwords = _build_container()

    try:
        if args.command == "encrypt":
            output = args.output or args.input.with_suffix(args.input.suffix + ".enc")
            use_case = EncryptFileUseCase(crypto, deriver, files, passwords)
            result = use_case.execute(EncryptRequest(input_path=args.input, output_path=output))
        else:
            output = args.output or args.input.with_suffix(".dec.txt")
            use_case = DecryptFileUseCase(crypto, deriver, files, passwords)
            result = use_case.execute(DecryptRequest(input_path=args.input, output_path=output))

        print(f"OK: {result.output_path} ({result.bytes_written} bytes)")
        return 0

    except CryptoError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
