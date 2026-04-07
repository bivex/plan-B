# Cryptex

CLI-утилита для шифрования файлов симметричным ключом (паролем).

## Алгоритмы

| Компонент | Алгоритм | Параметры |
|---|---|---|
| Шифр | **AES-256-GCM** (AEAD) | ключ 256 бит, nonce 96 бит, tag 128 бит |
| KDF | **scrypt** | N=16384, r=8, p=1 |
| Salt | `os.urandom` | 32 байта |
| Nonce | `os.urandom` | 12 байт |

### Почему именно так

- **AES-256-GCM** — шифрование + аутентификация целостности за одну операцию (AEAD). Любое изменение ciphertext или tag будет обнаружено при расшифровке.
- **scrypt** — KDF, устойчивый к GPU/ASIC брутфорсу (в отличие от PBKDF2). Параметры соответствуют рекомендациям OWASP.
- **256-битный ключ** — полный размер AES-256, без компромиссов.
- **Случайный salt + nonce** для каждой операции — один и тот же пароль никогда не даёт одинаковый ciphertext.

### Формат зашифрованного файла

```
| salt (32 байта) | nonce (12 байт) | tag (16 байт) | ciphertext (...) |
```

## Установка

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Использование

```bash
# Зашифровать
cryptex encrypt secret.txt
# → secret.txt.enc

# Расшифровать
cryptex decrypt secret.txt.enc
# → secret.txt.enc.dec.txt

# С явным выходным файлом
cryptex encrypt secret.txt -o encrypted.bin
cryptex decrypt encrypted.bin -o restored.txt
```

Пароль вводится через терминал (getpass), не сохраняется в history.

## Архитектура

Hexagonal (ports & adapters):

```
presentation/cli     → argparse, DI wiring
    ↓
application/use_cases → EncryptFileUseCase, DecryptFileUseCase
    ↓ (порты)
domain/value_objects  → Salt, Nonce, Key, Ciphertext, Password
    ↓ (адаптеры)
infrastructure/       → AesGcmEngine, ScryptKeyDeriver, DiskFileRepository, CliPasswordProvider
```

Домен и use cases не зависят от конкретных реализаций — только от абстрактных портов. Это позволяет подменять криптодвижок, KDF, хранилище и источник пароля без изменения бизнес-логики.

## Тесты

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

24 теста: unit (domain value objects + use cases с in-memory fakes) + integration (полный цикл AES-256-GCM + scrypt на реальной файловой системе).

## Требования

- Python >= 3.11
- cryptography >= 42.0
