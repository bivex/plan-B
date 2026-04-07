#!/usr/bin/env python3
"""Decrypt a .enc file. Usage: python decrypt.py <file.enc> [password]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from cryptex.application.dtos import DecryptRequest
from cryptex.application.use_cases.decrypt_file import DecryptFileUseCase
from cryptex.domain.value_objects import Password
from cryptex.infrastructure.cli.password_provider import PasswordProvider
from cryptex.infrastructure.crypto.aes_gcm_engine import AesGcmEngine
from cryptex.infrastructure.io.file_repository import DiskFileRepository
from cryptex.infrastructure.kdf.scrypt_deriver import ScryptKeyDeriver


class ArgPw(PasswordProvider):
    def __init__(self, pw: str):
        self._pw = pw

    def get_password(self, *, confirm=False):
        return Password(self._pw.encode())


class PromptPw(PasswordProvider):
    def get_password(self, *, confirm=False):
        import getpass
        pw = getpass.getpass("Password: ")
        if not pw:
            raise SystemExit("Empty password")
        return Password(pw.encode())


def main():
    if len(sys.argv) < 2:
        print("Usage: python decrypt.py <file.enc> [password]")
        print("       If password omitted — will prompt")
        sys.exit(1)

    src = Path(sys.argv[1])
    if not src.exists():
        print(f"File not found: {src}")
        sys.exit(1)

    dst = src.with_suffix(".dec.txt")

    pw = ArgPw(sys.argv[2]) if len(sys.argv) > 2 else PromptPw()

    try:
        uc = DecryptFileUseCase(AesGcmEngine(), ScryptKeyDeriver(), DiskFileRepository(), pw)
        result = uc.execute(DecryptRequest(src, dst))
        print(f"OK: {result.output_path} ({result.bytes_written} bytes)")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
