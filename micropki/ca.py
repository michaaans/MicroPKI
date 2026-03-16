"""
Главный модуль удостоверяющего центра.

Содержит:
- init_root_ca()  — полная процедура инициализации корневого CA
- generate_policy_file() — создание policy.txt
- validate_args() — валидация аргументов CLI
- main()          — точка входа (entry point из pyproject.toml)
"""

import sys
import os
import datetime
import logging
from pathlib import Path

from micropki.cli import create_parser
from micropki.logger import setup_logger
from micropki.crypto_utils import (
    generate_private_key,
    serialize_private_key_pem,
    save_private_key,
    read_passphrase,
)
from micropki.certificates import (
    parse_subject_dn,
    build_root_ca_certificate,
    serialize_certificate_pem,
)


def validate_args(args) -> list[str]:
    """
    Валидация аргументов после парсинга.
    Возвращает список строк с ошибками. Пустой список = всё корректно.

    Проверки:
      - subject непустой
      - key-size соответствует key-type (4096↔rsa, 384↔ecc)
      - passphrase-file существует и читаем
      - validity-days > 0
      - out-dir не является обычным файлом; если существует — доступен для записи
    """
    errors: list[str] = []

    if not args.subject or not args.subject.strip():
        errors.append("--subject должен быть не пустой строкой.")

    # key-size по умолчанию, если не указан
    if args.key_size is None:
        if args.key_type == "rsa":
            args.key_size = 4096
        else:
            args.key_size = 384

    if args.key_type == "rsa" and args.key_size != 4096:
        errors.append(
            f"Для RSA, --key-size должен быть 4096, получено {args.key_size}."
        )
    if args.key_type == "ecc" and args.key_size != 384:
        errors.append(
            f"Для ECC, --key-size должен быть 384, получено {args.key_size}."
        )

    # passphrase-file
    pf: Path = args.passphrase_file
    if not pf.exists():
        errors.append(f"Файл с парольной фразой не существует: {pf}")
    elif not pf.is_file():
        errors.append(f"Путь к парольной фразе - необычный файл: {pf}")
    elif not os.access(pf, os.R_OK):
        errors.append(f"Файл с парольной фразой недоступен для чтения: {pf}")

    # validity-days
    if args.validity_days <= 0:
        errors.append(
            f"--validity-days должен быть положительным числом, получено {args.validity_days}."
        )

    # out-dir
    od: Path = args.out_dir
    if od.exists():
        if not od.is_dir():
            errors.append(f"--out-dir существует, но не является каталогом: {od}")
        elif not os.access(od, os.W_OK):
            errors.append(f"--out-dir недоступен для записи: {od}")

    return errors


def generate_policy_file(
    subject_dn_str: str,
    serial_number: int,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    key_type: str,
    key_size: int,
    out_dir: Path,
) -> Path:
    """
    Создаёт текстовый файл policy.txt с описанием политики УЦ.
    """
    algo_name = f"{key_type.upper()}-{key_size}"
    if key_type == "ecc":
        algo_name = f"ECC-P{key_size}"

    content = (
        "=== MicroPKI Certificate Policy ===\n"
        "\n"
        f"CA Name (Subject DN): {subject_dn_str}\n"
        f"Serial Number: 0x{serial_number:040X}\n"
        f"Validity Period:\n"
        f"  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"  Not After:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"Key Algorithm: {algo_name}\n"
        f"Purpose: Root CA for MicroPKI demonstration\n"
        f"Policy Version: 1.0\n"
        f"Created: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    )

    policy_path = out_dir / "policy.txt"
    policy_path.write_text(content, encoding="utf-8")
    return policy_path


def init_root_ca(
    subject: str,
    key_type: str,
    key_size: int,
    passphrase_file: Path,
    out_dir: Path,
    validity_days: int,
    logger: logging.Logger,
) -> None:
    """
    Полная процедура инициализации корневого удостоверяющего центра.

    1. Чтение парольной фразы
    2. Генерация пары ключей
    3. Парсинг DN и создание самоподписанного сертификата
    4. Сохранение зашифрованного ключа
    5. Сохранение сертификата
    6. Генерация policy.txt
    7. Обнуление парольной фразы в памяти (best effort)
    """
    passphrase: bytes = b""

    try:
        # 1. Парольная фраза
        logger.info("Чтение парольной фразы из файла")
        passphrase = read_passphrase(passphrase_file)

        # 2. Генерация ключа
        logger.info(
            "Запуск генерации ключа: type=%s, size=%d", key_type, key_size
        )
        private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа успешно завершена")

        # 3. Сертификат
        logger.info("Начало подписания сертификата")
        subject_name = parse_subject_dn(subject)
        certificate = build_root_ca_certificate(
            private_key=private_key,
            subject=subject_name,
            validity_days=validity_days,
            key_type=key_type,
        )
        logger.info("Подписание сертификата завершено успешно")

        # 4. Сохранение закрытого ключа
        private_dir = out_dir / "private"
        private_dir.mkdir(parents=True, exist_ok=True)

        key_pem = serialize_private_key_pem(private_key, passphrase)
        key_path = private_dir / "ca.key.pem"
        save_private_key(key_pem, key_path)
        logger.info("Закрытый ключ, сохранен в %s", key_path.resolve())

        # 5. Сохранение сертификата
        certs_dir = out_dir / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)

        cert_pem = serialize_certificate_pem(certificate)
        cert_path = certs_dir / "ca.cert.pem"
        cert_path.write_bytes(cert_pem)
        logger.info("Сертификат, сохранен в %s", cert_path.resolve())

        # 6. policy.txt
        policy_path = generate_policy_file(
            subject_dn_str=subject,
            serial_number=certificate.serial_number,
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            key_type=key_type,
            key_size=key_size,
            out_dir=out_dir,
        )
        logger.info("Файл политики, создан в %s", policy_path.resolve())

        logger.info("Инициализация корневого центра сертификации успешно завершена")

    finally:
        if passphrase:
            ba = bytearray(passphrase)
            for i in range(len(ba)):
                ba[i] = 0
            del ba
            del passphrase


def main() -> None:
    """
    Точка входа CLI:
    """
    parser = create_parser()
    args = parser.parse_args()

    # Если не указана ни одна подкоманда
    if args.command is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.command == "ca" and getattr(args, "ca_action", None) is None:
        parser.parse_args(["ca", "--help"])
        sys.exit(1)

    # ---- ca init ----
    if args.command == "ca" and args.ca_action == "init":

        logger = setup_logger(args.log_file)

        errors = validate_args(args)
        if errors:
            for err in errors:
                logger.error("Ошибка валидации: %s", err)
                print(f"Ошибка: {err}", file=sys.stderr)
            sys.exit(1)

        try:
            init_root_ca(
                subject=args.subject,
                key_type=args.key_type,
                key_size=args.key_size,
                passphrase_file=args.passphrase_file,
                out_dir=args.out_dir,
                validity_days=args.validity_days,
                logger=logger,
            )
        except Exception as exc:
            logger.error("Не удалось выполнить инициализацию центра сертификации: %s", exc)
            print(f"Ошибка: {exc}", file=sys.stderr)
            sys.exit(1)