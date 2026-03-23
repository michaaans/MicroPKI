"""
Главный модуль удостоверяющего центра.

Содержит:
- init_root_ca()              — инициализация корневого CA
- issue_intermediate()        — создание промежуточного CA
- issue_leaf_cert()           — выпуск конечного сертификата
- validate_* функции          — валидация аргументов CLI
- main()                      — точка входа
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
    serialize_private_key_pem_unencrypted,
    save_key_file,
    read_passphrase,
    load_encrypted_private_key,
    load_certificate,
    get_cn_from_subject,
    sanitize_filename,
)
from micropki.certificates import (
    parse_subject_dn,
    build_root_ca_certificate,
    build_intermediate_certificate,
    build_leaf_certificate,
    parse_san_entries,
    serialize_certificate_pem,
)
from micropki.csr import build_intermediate_csr, serialize_csr_pem
from micropki.templates import get_template, validate_san_types


def validate_init_args(args) -> list[str]:
    """
    Валидация аргументов для ca init.

    :param args: объект аргументов argparse
    :return: список ошибок (пустой = всё корректно)
    """
    errors: list[str] = []

    if not args.subject or not args.subject.strip():
        errors.append("--subject должен быть непустой строкой.")

    if args.key_size is None:
        args.key_size = 4096 if args.key_type == "rsa" else 384

    if args.key_type == "rsa" and args.key_size != 4096:
        errors.append(f"Для RSA --key-size должен быть 4096, получено {args.key_size}.")
    if args.key_type == "ecc" and args.key_size != 384:
        errors.append(f"Для ECC --key-size должен быть 384, получено {args.key_size}.")

    errors.extend(_validate_passphrase_file(args.passphrase_file))
    errors.extend(_validate_positive_int(args.validity_days, "--validity-days"))
    errors.extend(_validate_out_dir(args.out_dir))

    return errors


def validate_intermediate_args(args) -> list[str]:
    """
    Валидация аргументов для ca issue-intermediate.

    :param args: объект аргументов argparse
    :return: список ошибок
    """
    errors: list[str] = []

    if not args.subject or not args.subject.strip():
        errors.append("--subject должен быть непустой строкой.")

    if args.key_size is None:
        args.key_size = 4096 if args.key_type == "rsa" else 384

    if args.key_type == "rsa" and args.key_size != 4096:
        errors.append(f"Для RSA --key-size должен быть 4096, получено {args.key_size}.")
    if args.key_type == "ecc" and args.key_size != 384:
        errors.append(f"Для ECC --key-size должен быть 384, получено {args.key_size}.")

    errors.extend(_validate_file_exists(args.root_cert, "--root-cert"))
    errors.extend(_validate_file_exists(args.root_key, "--root-key"))
    errors.extend(_validate_passphrase_file(args.root_pass_file))
    errors.extend(_validate_passphrase_file(args.passphrase_file))
    errors.extend(_validate_positive_int(args.validity_days, "--validity-days"))
    errors.extend(_validate_out_dir(args.out_dir))

    if args.pathlen < 0:
        errors.append(f"--pathlen должен быть ≥ 0, получено {args.pathlen}.")

    return errors


def validate_issue_cert_args(args) -> list[str]:
    """
    Валидация аргументов для ca issue-cert.

    :param args: объект аргументов argparse
    :return: список ошибок
    """
    errors: list[str] = []

    if not args.subject or not args.subject.strip():
        errors.append("--subject должен быть непустой строкой.")

    # Размер ключа по умолчанию для конечных субъектов
    if args.key_size is None:
        args.key_size = 2048 if args.key_type == "rsa" else 256

    errors.extend(_validate_file_exists(args.ca_cert, "--ca-cert"))
    errors.extend(_validate_file_exists(args.ca_key, "--ca-key"))
    errors.extend(_validate_passphrase_file(args.ca_pass_file))
    errors.extend(_validate_positive_int(args.validity_days, "--validity-days"))
    errors.extend(_validate_out_dir(args.out_dir))

    # Валидация SAN
    try:
        san_entries = parse_san_entries(args.san)
        template = get_template(args.template)
        san_errors = validate_san_types(template, san_entries)
        errors.extend(san_errors)
    except ValueError as e:
        errors.append(str(e))

    return errors


def _validate_file_exists(path: Path, name: str) -> list[str]:
    """Проверяет, что файл существует и доступен для чтения."""
    errors: list[str] = []
    if not path.exists():
        errors.append(f"Файл {name} не существует: {path}")
    elif not path.is_file():
        errors.append(f"{name} не является файлом: {path}")
    elif not os.access(path, os.R_OK):
        errors.append(f"Файл {name} недоступен для чтения: {path}")
    return errors


def _validate_passphrase_file(path: Path) -> list[str]:
    """Проверяет файл парольной фразы."""
    return _validate_file_exists(path, "--passphrase-file")


def _validate_positive_int(value: int, name: str) -> list[str]:
    """Проверяет, что значение — положительное целое число."""
    if value <= 0:
        return [f"{name} должен быть положительным числом, получено {value}."]
    return []


def _validate_out_dir(path: Path) -> list[str]:
    """Проверяет выходной каталог."""
    errors: list[str] = []
    if path.exists():
        if not path.is_dir():
            errors.append(f"--out-dir существует, но не является каталогом: {path}")
        elif not os.access(path, os.W_OK):
            errors.append(f"--out-dir недоступен для записи: {path}")
    return errors


def check_existing_files(
    file_paths: list[Path],
    force: bool,
    logger: logging.Logger,
) -> None:
    """
    Проверяет, существуют ли файлы, которые будут перезаписаны.

    :param file_paths: список путей к файлам для проверки
    :param force: разрешена ли перезапись
    :param logger: логгер
    :raises SystemExit: если файлы существуют и --force не указан
    """
    existing = [p for p in file_paths if p.exists()]

    if not existing:
        return

    file_list = ", ".join(str(p) for p in existing)

    if force:
        logger.warning(
            "Флаг --force указан. Следующие файлы будут перезаписаны: %s",
            file_list,
        )
    else:
        logger.error(
            "Следующие файлы уже существуют: %s. "
            "Используйте --force для перезаписи.",
            file_list,
        )
        print(
            "Ошибка: Следующие файлы уже существуют и будут перезаписаны:\n",
            file=sys.stderr,
        )
        for p in existing:
            print(f"  - {p}", file=sys.stderr)
        print(
            "\nИспользуйте --force для принудительной перезаписи.",
            file=sys.stderr,
        )
        sys.exit(1)


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

    :return: путь к созданному файлу
    """
    algo_name = f"ECC-P{key_size}" if key_type == "ecc" else f"{key_type.upper()}-{key_size}"

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


def append_intermediate_policy(
    out_dir: Path,
    subject_dn_str: str,
    serial_number: int,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    key_type: str,
    key_size: int,
    path_length: int,
    issuer_dn_str: str,
) -> Path:
    """
    Дополняет policy.txt информацией о промежуточном УЦ.

    :return: путь к обновлённому файлу
    """
    algo_name = f"ECC-P{key_size}" if key_type == "ecc" else f"{key_type.upper()}-{key_size}"

    section = (
        "\n"
        "=== Intermediate CA ===\n"
        "\n"
        f"Subject DN: {subject_dn_str}\n"
        f"Issuer DN: {issuer_dn_str}\n"
        f"Serial Number: 0x{serial_number:040X}\n"
        f"Validity Period:\n"
        f"  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"  Not After:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"Key Algorithm: {algo_name}\n"
        f"Path Length Constraint: {path_length}\n"
        f"Purpose: Intermediate CA for MicroPKI\n"
        f"Added: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    )

    policy_path = out_dir / "policy.txt"

    with open(policy_path, "a", encoding="utf-8") as f:
        f.write(section)

    return policy_path


def init_root_ca(
    subject: str,
    key_type: str,
    key_size: int,
    passphrase_file: Path,
    out_dir: Path,
    validity_days: int,
    force: bool,
    logger: logging.Logger,
) -> None:
    """
    Полная процедура инициализации корневого УЦ.

    :param subject: DN субъекта
    :param key_type: тип ключа
    :param key_size: размер ключа
    :param passphrase_file: путь к файлу с парольной фразой
    :param out_dir: выходной каталог
    :param validity_days: срок действия
    :param force: перезаписывать существующие файлы
    :param logger: логгер
    """
    passphrase: bytes = b""

    try:
        key_path = out_dir / "private" / "ca.key.pem"
        cert_path = out_dir / "certs" / "ca.cert.pem"
        policy_path = out_dir / "policy.txt"
        check_existing_files([key_path, cert_path, policy_path], force, logger)

        logger.info("Чтение парольной фразы из файла")
        passphrase = read_passphrase(passphrase_file)

        logger.info("Запуск генерации ключа: type=%s, size=%d", key_type, key_size)
        private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа успешно завершена")

        logger.info("Начало подписания сертификата")
        subject_name = parse_subject_dn(subject)
        certificate = build_root_ca_certificate(
            private_key=private_key,
            subject=subject_name,
            validity_days=validity_days,
            key_type=key_type,
        )
        logger.info("Подписание сертификата завершено успешно")

        private_dir = out_dir / "private"
        private_dir.mkdir(parents=True, exist_ok=True)

        key_pem = serialize_private_key_pem(private_key, passphrase)
        save_key_file(key_pem, key_path)
        logger.info("Закрытый ключ сохранён в %s", key_path.resolve())

        certs_dir = out_dir / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)

        cert_pem = serialize_certificate_pem(certificate)
        cert_path.write_bytes(cert_pem)
        logger.info("Сертификат сохранён в %s", cert_path.resolve())

        policy_path = generate_policy_file(
            subject_dn_str=subject,
            serial_number=certificate.serial_number,
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            key_type=key_type,
            key_size=key_size,
            out_dir=out_dir,
        )
        logger.info("Файл политики создан в %s", policy_path.resolve())
        logger.info("Инициализация корневого УЦ успешно завершена")

    finally:
        if passphrase:
            ba = bytearray(passphrase)
            for i in range(len(ba)):
                ba[i] = 0
            del ba, passphrase


def issue_intermediate(
    root_cert_path: Path,
    root_key_path: Path,
    root_pass_file: Path,
    subject: str,
    key_type: str,
    key_size: int,
    passphrase_file: Path,
    out_dir: Path,
    validity_days: int,
    path_length: int,
    force: bool,
    logger: logging.Logger,
) -> None:
    """
    Создание промежуточного УЦ.

    1. Загружает сертификат и ключ корневого CA
    2. Генерирует ключ для промежуточного CA
    3. Создаёт CSR
    4. Подписывает CSR корневым CA
    5. Сохраняет зашифрованный ключ и сертификат
    6. Обновляет policy.txt
    """
    root_passphrase: bytes = b""
    inter_passphrase: bytes = b""

    try:
        key_path = out_dir / "private" / "intermediate.key.pem"
        cert_path = out_dir / "certs" / "intermediate.cert.pem"
        check_existing_files([key_path, cert_path], force, logger)

        # 1. Загрузка корневого CA
        logger.info("Чтение парольной фразы корневого УЦ")
        root_passphrase = read_passphrase(root_pass_file)

        logger.info("Загрузка сертификата корневого УЦ из %s", root_cert_path)
        root_cert = load_certificate(root_cert_path)

        logger.info("Загрузка закрытого ключа корневого УЦ из %s", root_key_path)
        root_private_key = load_encrypted_private_key(root_key_path, root_passphrase)

        # 2. Генерация ключа промежуточного CA
        logger.info("Запуск генерации ключа промежуточного УЦ: type=%s, size=%d", key_type, key_size)
        inter_private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа промежуточного УЦ завершена")

        # 3. Создание CSR
        logger.info("Генерация CSR для промежуточного УЦ")
        subject_name = parse_subject_dn(subject)
        csr = build_intermediate_csr(
            private_key=inter_private_key,
            subject=subject_name,
            path_length=path_length,
            key_type=key_type,
        )
        logger.info("CSR для промежуточного УЦ создан")

        # Сохраняем CSR (опционально)
        csrs_dir = out_dir / "csrs"
        csrs_dir.mkdir(parents=True, exist_ok=True)
        csr_pem = serialize_csr_pem(csr)
        csr_path = csrs_dir / "intermediate.csr.pem"
        csr_path.write_bytes(csr_pem)

        # 4. Подписание CSR корневым CA
        logger.info("Подписание сертификата промежуточного УЦ корневым УЦ")
        inter_cert = build_intermediate_certificate(
            csr=csr,
            root_private_key=root_private_key,
            root_cert=root_cert,
            validity_days=validity_days,
            path_length=path_length,
        )
        logger.info("Подписание сертификата промежуточного УЦ завершено")

        # 5. Сохранение ключа
        logger.info("Чтение парольной фразы промежуточного УЦ")
        inter_passphrase = read_passphrase(passphrase_file)

        private_dir = out_dir / "private"
        private_dir.mkdir(parents=True, exist_ok=True)
        inter_key_pem = serialize_private_key_pem(inter_private_key, inter_passphrase)
        save_key_file(inter_key_pem, key_path)
        logger.info("Закрытый ключ промежуточного УЦ сохранён в %s", key_path.resolve())

        # 6. Сохранение сертификата
        certs_dir = out_dir / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        inter_cert_pem = serialize_certificate_pem(inter_cert)
        cert_path.write_bytes(inter_cert_pem)
        logger.info("Сертификат промежуточного УЦ сохранён в %s", cert_path.resolve())

        # 7. Обновление policy.txt
        issuer_dn = ", ".join(
            f"{attr.oid._name}={attr.value}" for attr in root_cert.subject
        )
        policy_path = append_intermediate_policy(
            out_dir=out_dir,
            subject_dn_str=subject,
            serial_number=inter_cert.serial_number,
            not_before=inter_cert.not_valid_before_utc,
            not_after=inter_cert.not_valid_after_utc,
            key_type=key_type,
            key_size=key_size,
            path_length=path_length,
            issuer_dn_str=issuer_dn,
        )
        logger.info("Файл политики обновлён в %s", policy_path.resolve())
        logger.info("Создание промежуточного УЦ успешно завершено")

    finally:
        for secret in (root_passphrase, inter_passphrase):
            if secret:
                ba = bytearray(secret)
                for i in range(len(ba)):
                    ba[i] = 0
                del ba


def issue_leaf_cert(
    ca_cert_path: Path,
    ca_key_path: Path,
    ca_pass_file: Path,
    template_name: str,
    subject: str,
    san_strings: list[str],
    key_type: str,
    key_size: int,
    out_dir: Path,
    validity_days: int,
    logger: logging.Logger,
) -> None:
    """
    Выпуск конечного сертификата по шаблону.

    1. Загружает сертификат и ключ промежуточного CA
    2. Генерирует ключ для конечного субъекта
    3. Применяет шаблон и SAN
    4. Подписывает конечный сертификат
    5. Сохраняет незашифрованный ключ и сертификат
    """
    ca_passphrase: bytes = b""

    try:
        # 1. Загрузка промежуточного CA
        logger.info("Чтение парольной фразы промежуточного УЦ")
        ca_passphrase = read_passphrase(ca_pass_file)

        logger.info("Загрузка сертификата промежуточного УЦ из %s", ca_cert_path)
        ca_cert = load_certificate(ca_cert_path)

        logger.info("Загрузка закрытого ключа промежуточного УЦ из %s", ca_key_path)
        ca_private_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

        # 2. Получаем шаблон
        template = get_template(template_name)

        # 3. Парсинг SAN
        san_entries = parse_san_entries(san_strings)

        # 4. Генерация ключа конечного субъекта
        logger.info(
            "Генерация ключа конечного субъекта: type=%s, size=%d",
            key_type, key_size,
        )
        leaf_private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа конечного субъекта завершена")

        # 5. Создание сертификата
        logger.info(
            "Начало выпуска сертификата: шаблон=%s, субъект=%s, SAN=%s",
            template_name, subject, san_strings,
        )
        subject_name = parse_subject_dn(subject)
        leaf_cert = build_leaf_certificate(
            subject=subject_name,
            leaf_public_key=leaf_private_key.public_key(),
            ca_private_key=ca_private_key,
            ca_cert=ca_cert,
            template=template,
            san_entries=san_entries,
            validity_days=validity_days,
            leaf_key_type=key_type,
        )
        logger.info("Выпуск конечного сертификата завершён успешно")

        # 6. Формирование имён файлов
        cn = get_cn_from_subject(subject_name)
        safe_name = sanitize_filename(cn)
        cert_filename = f"{safe_name}.cert.pem"
        key_filename = f"{safe_name}.key.pem"

        # 7. Сохранение сертификата
        out_dir.mkdir(parents=True, exist_ok=True)
        cert_path = out_dir / cert_filename
        cert_pem = serialize_certificate_pem(leaf_cert)
        cert_path.write_bytes(cert_pem)
        logger.info("Сертификат сохранён в %s", cert_path.resolve())

        # 8. Сохранение незашифрованного ключа
        key_path = out_dir / key_filename
        key_pem = serialize_private_key_pem_unencrypted(leaf_private_key)
        save_key_file(key_pem, key_path)
        logger.warning(
            "Закрытый ключ сохранён БЕЗ ШИФРОВАНИЯ в %s. "
            "Обеспечьте защиту файла вручную!",
            key_path.resolve(),
        )

        # 9. Аудиторский след
        logger.info(
            "Аудит выпуска: serial=0x%040X, subject=%s, template=%s, SAN=%s",
            leaf_cert.serial_number,
            subject,
            template_name,
            san_strings,
        )

    finally:
        if ca_passphrase:
            ba = bytearray(ca_passphrase)
            for i in range(len(ba)):
                ba[i] = 0
            del ba


def main() -> None:
    """
    Точка входа CLI. Вызывается через console_scripts: micropki
    """
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.command == "ca" and getattr(args, "ca_action", None) is None:
        parser.parse_args(["ca", "--help"])
        sys.exit(1)

    # ── ca init ──
    if args.command == "ca" and args.ca_action == "init":
        logger = setup_logger(args.log_file)
        errors = validate_init_args(args)
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
                force=args.force,
                logger=logger,
            )
        except SystemExit:
            raise
        except Exception as exc:
            logger.error("Не удалось выполнить инициализацию: %s", exc)
            print(f"Ошибка: {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "ca" and args.ca_action == "issue-intermediate":
        logger = setup_logger(args.log_file)
        errors = validate_intermediate_args(args)
        if errors:
            for err in errors:
                logger.error("Ошибка валидации: %s", err)
                print(f"Ошибка: {err}", file=sys.stderr)
            sys.exit(1)
        try:
            issue_intermediate(
                root_cert_path=args.root_cert,
                root_key_path=args.root_key,
                root_pass_file=args.root_pass_file,
                subject=args.subject,
                key_type=args.key_type,
                key_size=args.key_size,
                passphrase_file=args.passphrase_file,
                out_dir=args.out_dir,
                validity_days=args.validity_days,
                path_length=args.pathlen,
                force=args.force,
                logger=logger,
            )
        except SystemExit:
            raise
        except Exception as exc:
            logger.error("Не удалось создать промежуточный УЦ: %s", exc)
            print(f"Ошибка: {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "ca" and args.ca_action == "issue-cert":
        logger = setup_logger(args.log_file)
        errors = validate_issue_cert_args(args)
        if errors:
            for err in errors:
                logger.error("Ошибка валидации: %s", err)
                print(f"Ошибка: {err}", file=sys.stderr)
            sys.exit(1)
        try:
            issue_leaf_cert(
                ca_cert_path=args.ca_cert,
                ca_key_path=args.ca_key,
                ca_pass_file=args.ca_pass_file,
                template_name=args.template,
                subject=args.subject,
                san_strings=args.san,
                key_type=args.key_type,
                key_size=args.key_size,
                out_dir=args.out_dir,
                validity_days=args.validity_days,
                logger=logger,
            )
        except SystemExit:
            raise
        except Exception as exc:
            logger.error("Не удалось выпустить сертификат: %s", exc)
            print(f"Ошибка: {exc}", file=sys.stderr)
            sys.exit(1)