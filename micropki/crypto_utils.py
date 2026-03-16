"""
Криптографические утилиты:
- генерация ключей RSA-4096 и ECC P-384
- сериализация закрытого ключа в зашифрованный PEM (PKCS#8)
- безопасное сохранение ключа на диск с ограниченными правами
- чтение парольной фразы из файла
- загрузка зашифрованного ключа (для тестов / верификации)
"""

import os
import platform
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("micropki")


def generate_private_key(key_type: str, key_size: int) -> PrivateKeyTypes:
    """
    Генерирует закрытый ключ.

    key_type: 'rsa' | 'ecc'
    key_size: 4096 (RSA) | 384 (ECC) — уже провалидировано в CLI/валидаторе
    """
    if key_type == "rsa":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    if key_type == "ecc":
        return ec.generate_private_key(curve=ec.SECP384R1())

    raise ValueError(f"Не поддерживаемый тип ключа: {key_type}")


def serialize_private_key_pem(private_key: PrivateKeyTypes, passphrase: bytes,) -> bytes:
    """
    Сериализует закрытый ключ → зашифрованный PEM (PKCS#8).

    Используется BestAvailableEncryption, который выберет
    AES-256-CBC + scrypt/PBKDF2 в зависимости от версии библиотеки.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def save_private_key(pem_data: bytes, file_path: Path) -> None:
    """
    Сохраняет зашифрованный PEM на диск.

    На Unix-подобных ОС:
      - каталог private/ → 0o700
      - файл ca.key.pem  → 0o600
    На Windows выдаёт предупреждение о невозможности
    установить POSIX-права.
    """
    is_windows = platform.system() == "Windows"

    # Создаём каталог
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if not is_windows:
        try:
            os.chmod(file_path.parent, 0o700)
        except OSError as exc:
            logger.warning(
                "Не удалось установить права доступа к каталогу 0700 для %s: %s",
                file_path.parent, exc,
            )
    else:
        logger.warning(
            "Обнаружена Windows — разрешения POSIX не поддерживаются."
            "Убедитесь, что '%s' защищен вручную.",
            file_path.parent,
        )

    # Записываем файл
    file_path.write_bytes(pem_data)

    if not is_windows:
        try:
            os.chmod(file_path, 0o600)
        except OSError as exc:
            logger.warning(
                "Не удалось установить права доступа к файлам 0600 для %s: %s",
                file_path, exc,
            )


def read_passphrase(passphrase_file: Path) -> bytes:
    """
    Читает парольную фразу из файла.

    - Читаем как сырые байты (без декодирования).
    - Убираем завершающие \\n / \\r\\n.
    - Парольная фраза НЕ логируется.
    """
    raw: bytes = passphrase_file.read_bytes()
    return raw.rstrip(b"\r\n").rstrip(b"\n")


def load_encrypted_private_key(pem_path: Path, passphrase: bytes, ) -> PrivateKeyTypes:
    """
    Загружает зашифрованный закрытый ключ обратно в память.
    Используется для тестов и верификации.
    """
    pem_data = pem_path.read_bytes()
    return serialization.load_pem_private_key(
        data=pem_data,
        password=passphrase,
    )