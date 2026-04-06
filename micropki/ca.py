"""
Главный модуль удостоверяющего центра.

Содержит все операции CA:
- init_root_ca         — инициализация корневого CA
- issue_intermediate   — создание промежуточного CA
- issue_leaf_cert      — выпуск конечного сертификата
- issue_ocsp_cert      — выпуск сертификата OCSP-ответчика
- list_certs_cmd       — вывод списка сертификатов
- show_cert_cmd        — вывод конкретного сертификата
- main                 — точка входа CLI
"""

import sys
import os
import json
import csv
import io
import datetime
import logging
from pathlib import Path

from micropki.cli import create_parser
from micropki.logger import setup_logger
from micropki.config import load_config
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
    build_ocsp_cert,
    parse_san_entries,
    serialize_certificate_pem,
)
from micropki.csr import build_intermediate_csr, serialize_csr_pem
from micropki.templates import get_template, validate_san_types
from micropki.database import init_database, check_schema
from micropki.repository import (
    insert_certificate,
    get_certificate_by_serial,
    list_certificates,
)
from micropki.serial import generate_unique_serial, serial_to_hex, is_valid_hex


def validate_init_args(args) -> list[str]:
    """Валидация аргументов для ca init."""
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
    """Валидация аргументов для ca issue-intermediate."""
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
    """Валидация аргументов для ca issue-cert."""
    errors: list[str] = []
    if not args.subject or not args.subject.strip():
        errors.append("--subject должен быть непустой строкой.")
    if args.key_size is None:
        args.key_size = 2048 if args.key_type == "rsa" else 256
    errors.extend(_validate_file_exists(args.ca_cert, "--ca-cert"))
    errors.extend(_validate_file_exists(args.ca_key, "--ca-key"))
    errors.extend(_validate_passphrase_file(args.ca_pass_file))
    errors.extend(_validate_positive_int(args.validity_days, "--validity-days"))
    errors.extend(_validate_out_dir(args.out_dir))
    try:
        san_entries = parse_san_entries(args.san)
        template = get_template(args.template)
        san_errors = validate_san_types(template, san_entries)
        errors.extend(san_errors)
    except ValueError as e:
        errors.append(str(e))
    return errors


def _validate_file_exists(path: Path, name: str) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        errors.append(f"Файл {name} не существует: {path}")
    elif not path.is_file():
        errors.append(f"{name} не является файлом: {path}")
    elif not os.access(path, os.R_OK):
        errors.append(f"Файл {name} недоступен для чтения: {path}")
    return errors


def _validate_passphrase_file(path: Path) -> list[str]:
    return _validate_file_exists(path, "--passphrase-file")


def _validate_positive_int(value: int, name: str) -> list[str]:
    if value <= 0:
        return [f"{name} должен быть положительным числом, получено {value}."]
    return []


def _validate_out_dir(path: Path) -> list[str]:
    errors: list[str] = []
    if path.exists():
        if not path.is_dir():
            errors.append(f"--out-dir существует, но не является каталогом: {path}")
        elif not os.access(path, os.W_OK):
            errors.append(f"--out-dir недоступен для записи: {path}")
    return errors


def check_existing_files(file_paths: list[Path], force: bool, logger: logging.Logger) -> None:
    """Проверяет существующие файлы перед перезаписью."""
    existing = [p for p in file_paths if p.exists()]
    if not existing:
        return
    file_list = ", ".join(str(p) for p in existing)
    if force:
        logger.warning("Флаг --force указан. Файлы будут перезаписаны: %s", file_list)
    else:
        logger.error("Файлы уже существуют: %s. Используйте --force.", file_list)
        print("Ошибка: Файлы уже существуют:", file=sys.stderr)
        for p in existing:
            print(f"  - {p}", file=sys.stderr)
        print("\nИспользуйте --force для перезаписи.", file=sys.stderr)
        sys.exit(1)


def _dn_to_string(name) -> str:
    """Преобразует x509.Name в строку DN."""
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def _save_cert_to_db(
    db_path: Path | None,
    certificate,
    cert_pem: str,
    logger: logging.Logger,
) -> None:
    """Вставляет сертификат в БД (если db_path указан и БД инициализирована)."""
    if db_path is None:
        return

    if not check_schema(db_path):
        logger.warning(
            "БД не инициализирована (%s). Сертификат НЕ записан в БД. "
            "Выполните 'micropki db init'.",
            db_path,
        )
        return

    serial_hex = serial_to_hex(certificate.serial_number)
    subject_str = _dn_to_string(certificate.subject)
    issuer_str = _dn_to_string(certificate.issuer)

    try:
        insert_certificate(
            db_path=db_path,
            serial_hex=serial_hex,
            subject=subject_str,
            issuer=issuer_str,
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            cert_pem=cert_pem if isinstance(cert_pem, str) else cert_pem.decode("utf-8"),
        )
    except Exception as e:
        logger.error("Ошибка записи сертификата в БД: %s", e)
        raise


def generate_policy_file(subject_dn_str, serial_number, not_before, not_after,
                         key_type, key_size, out_dir) -> Path:
    """Создаёт текстовый файл policy.txt."""
    algo_name = f"ECC-P{key_size}" if key_type == "ecc" else f"{key_type.upper()}-{key_size}"
    content = (
        "=== MicroPKI Certificate Policy ===\n\n"
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
    policy_path = Path(out_dir) / "policy.txt"
    policy_path.write_text(content, encoding="utf-8")
    return policy_path


def append_intermediate_policy(out_dir, subject_dn_str, serial_number,
                               not_before, not_after, key_type, key_size,
                               path_length, issuer_dn_str) -> Path:
    """Дополняет policy.txt информацией о промежуточном УЦ."""
    algo_name = f"ECC-P{key_size}" if key_type == "ecc" else f"{key_type.upper()}-{key_size}"
    section = (
        "\n=== Intermediate CA ===\n\n"
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
    policy_path = Path(out_dir) / "policy.txt"
    with open(policy_path, "a", encoding="utf-8") as f:
        f.write(section)
    return policy_path


def init_root_ca(subject, key_type, key_size, passphrase_file, out_dir,
                 validity_days, force, logger, db_path=None):
    """Инициализация корневого УЦ."""
    passphrase: bytes = b""
    try:
        key_path = out_dir / "private" / "ca.key.pem"
        cert_path = out_dir / "certs" / "ca.cert.pem"
        policy_path = out_dir / "policy.txt"
        check_existing_files([key_path, cert_path, policy_path], force, logger)

        logger.info("Чтение парольной фразы из файла")
        passphrase = read_passphrase(passphrase_file)

        if db_path and check_schema(db_path):
            serial_number = generate_unique_serial(db_path)
        else:
            serial_number = None

        logger.info("Запуск генерации ключа: type=%s, size=%d", key_type, key_size)
        private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа успешно завершена")

        logger.info("Начало подписания сертификата")
        subject_name = parse_subject_dn(subject)
        certificate = build_root_ca_certificate(
            private_key=private_key, subject=subject_name,
            validity_days=validity_days, key_type=key_type,
            serial_number=serial_number,
        )
        logger.info("Подписание сертификата завершено успешно")

        cert_pem = serialize_certificate_pem(certificate)
        _save_cert_to_db(db_path, certificate, cert_pem, logger)

        private_dir = out_dir / "private"
        private_dir.mkdir(parents=True, exist_ok=True)
        key_pem = serialize_private_key_pem(private_key, passphrase)
        save_key_file(key_pem, key_path)
        logger.info("Закрытый ключ сохранён в %s", key_path.resolve())

        certs_dir = out_dir / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert_pem)
        logger.info("Сертификат сохранён в %s", cert_path.resolve())

        generate_policy_file(subject, certificate.serial_number,
                             certificate.not_valid_before_utc,
                             certificate.not_valid_after_utc,
                             key_type, key_size, out_dir)
        logger.info("Инициализация корневого УЦ успешно завершена")
    finally:
        if passphrase:
            ba = bytearray(passphrase)
            for i in range(len(ba)):
                ba[i] = 0


def issue_intermediate(root_cert_path, root_key_path, root_pass_file, subject,
                       key_type, key_size, passphrase_file, out_dir,
                       validity_days, path_length, force, logger, db_path=None):
    """Создание промежуточного УЦ."""
    root_passphrase: bytes = b""
    inter_passphrase: bytes = b""
    try:
        key_path = out_dir / "private" / "intermediate.key.pem"
        cert_path = out_dir / "certs" / "intermediate.cert.pem"
        check_existing_files([key_path, cert_path], force, logger)

        logger.info("Чтение парольной фразы корневого УЦ")
        root_passphrase = read_passphrase(root_pass_file)
        root_cert = load_certificate(root_cert_path)
        root_private_key = load_encrypted_private_key(root_key_path, root_passphrase)

        if db_path and check_schema(db_path):
            serial_number = generate_unique_serial(db_path)
        else:
            serial_number = None

        logger.info("Генерация ключа промежуточного УЦ: type=%s, size=%d", key_type, key_size)
        inter_private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа промежуточного УЦ завершена")

        logger.info("Генерация CSR для промежуточного УЦ")
        subject_name = parse_subject_dn(subject)
        csr = build_intermediate_csr(inter_private_key, subject_name, path_length, key_type)
        logger.info("CSR для промежуточного УЦ создан")

        csrs_dir = out_dir / "csrs"
        csrs_dir.mkdir(parents=True, exist_ok=True)
        csr_path = csrs_dir / "intermediate.csr.pem"
        csr_path.write_bytes(serialize_csr_pem(csr))

        logger.info("Подписание сертификата промежуточного УЦ корневым УЦ")
        inter_cert = build_intermediate_certificate(
            csr=csr, root_private_key=root_private_key, root_cert=root_cert,
            validity_days=validity_days, path_length=path_length,
            serial_number=serial_number,
        )
        logger.info("Подписание сертификата промежуточного УЦ завершено")

        cert_pem = serialize_certificate_pem(inter_cert)
        _save_cert_to_db(db_path, inter_cert, cert_pem, logger)

        logger.info("Чтение парольной фразы промежуточного УЦ")
        inter_passphrase = read_passphrase(passphrase_file)
        private_dir = out_dir / "private"
        private_dir.mkdir(parents=True, exist_ok=True)
        inter_key_pem = serialize_private_key_pem(inter_private_key, inter_passphrase)
        save_key_file(inter_key_pem, key_path)
        logger.info("Ключ промежуточного УЦ сохранён в %s", key_path.resolve())

        certs_dir = out_dir / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert_pem)
        logger.info("Сертификат промежуточного УЦ сохранён в %s", cert_path.resolve())

        issuer_dn = _dn_to_string(root_cert.subject)
        append_intermediate_policy(out_dir, subject, inter_cert.serial_number,
                                   inter_cert.not_valid_before_utc,
                                   inter_cert.not_valid_after_utc,
                                   key_type, key_size, path_length, issuer_dn)
        logger.info("Создание промежуточного УЦ успешно завершено")
    finally:
        for secret in (root_passphrase, inter_passphrase):
            if secret:
                ba = bytearray(secret)
                for i in range(len(ba)):
                    ba[i] = 0


def issue_leaf_cert(ca_cert_path, ca_key_path, ca_pass_file, template_name,
                    subject, san_strings, key_type, key_size, out_dir,
                    validity_days, logger, db_path=None):
    """Выпуск конечного сертификата по шаблону."""
    ca_passphrase: bytes = b""
    try:
        logger.info("Чтение парольной фразы промежуточного УЦ")
        ca_passphrase = read_passphrase(ca_pass_file)
        ca_cert = load_certificate(ca_cert_path)
        ca_private_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

        template = get_template(template_name)
        san_entries = parse_san_entries(san_strings)

        if db_path and check_schema(db_path):
            serial_number = generate_unique_serial(db_path)
        else:
            serial_number = None

        logger.info("Генерация ключа конечного субъекта: type=%s, size=%d", key_type, key_size)
        leaf_private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа конечного субъекта завершена")

        logger.info("Выпуск сертификата: шаблон=%s, субъект=%s, SAN=%s",
                     template_name, subject, san_strings)
        subject_name = parse_subject_dn(subject)
        leaf_cert = build_leaf_certificate(
            subject=subject_name, leaf_public_key=leaf_private_key.public_key(),
            ca_private_key=ca_private_key, ca_cert=ca_cert, template=template,
            san_entries=san_entries, validity_days=validity_days,
            leaf_key_type=key_type, serial_number=serial_number,
        )
        logger.info("Выпуск конечного сертификата завершён")

        cert_pem = serialize_certificate_pem(leaf_cert)
        _save_cert_to_db(db_path, leaf_cert, cert_pem, logger)

        cn = get_cn_from_subject(subject_name)
        safe_name = sanitize_filename(cn)
        cert_filename = f"{safe_name}.cert.pem"
        key_filename = f"{safe_name}.key.pem"

        out_dir.mkdir(parents=True, exist_ok=True)
        cert_path = out_dir / cert_filename
        cert_path.write_bytes(cert_pem)
        logger.info("Сертификат сохранён в %s", cert_path.resolve())

        key_path = out_dir / key_filename
        key_pem = serialize_private_key_pem_unencrypted(leaf_private_key)
        save_key_file(key_pem, key_path)
        logger.warning("Ключ сохранён БЕЗ ШИФРОВАНИЯ в %s", key_path.resolve())

        serial_hex = serial_to_hex(leaf_cert.serial_number)
        logger.info("Аудит: serial=%s, subject=%s, template=%s", serial_hex, subject, template_name)
    finally:
        if ca_passphrase:
            ba = bytearray(ca_passphrase)
            for i in range(len(ba)):
                ba[i] = 0


def issue_ocsp_cert(
    ca_cert_path, ca_key_path, ca_pass_file, subject,
    san_strings, key_type, key_size, out_dir, validity_days,
    logger, db_path=None,
):
    """
    Выпуск сертификата OCSP-ответчика.

    Профиль (OSC-1):
    - BasicConstraints: CA=FALSE (критическое)
    - KeyUsage: digitalSignature (критическое)
    - ExtendedKeyUsage: id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
    - Ключ хранится БЕЗ шифрования (0o600) — OSC-3
    """
    ca_passphrase: bytes = b""
    try:
        logger.info("Чтение парольной фразы УЦ для выпуска OCSP-сертификата")
        ca_passphrase = read_passphrase(ca_pass_file)
        ca_cert = load_certificate(ca_cert_path)
        ca_private_key = load_encrypted_private_key(ca_key_path, ca_passphrase)

        # Размер ключа по умолчанию (OSC-2)
        if key_size is None:
            key_size = 2048 if key_type == "rsa" else 256

        if db_path and check_schema(db_path):
            serial_number = generate_unique_serial(db_path)
        else:
            serial_number = None

        logger.info("Генерация ключа OCSP-ответчика: type=%s, size=%d", key_type, key_size)
        ocsp_private_key = generate_private_key(key_type, key_size)
        logger.info("Генерация ключа OCSP-ответчика завершена")

        san_entries = parse_san_entries(san_strings)
        subject_name = parse_subject_dn(subject)

        logger.info("Выпуск сертификата OCSP-ответчика: субъект=%s", subject)
        ocsp_certificate = build_ocsp_cert(
            subject=subject_name,
            ocsp_public_key=ocsp_private_key.public_key(),
            ca_private_key=ca_private_key,
            ca_cert=ca_cert,
            san_entries=san_entries,
            validity_days=validity_days,
            serial_number=serial_number,
        )
        logger.info("Сертификат OCSP-ответчика выпущен")

        cert_pem = serialize_certificate_pem(ocsp_certificate)
        _save_cert_to_db(db_path, ocsp_certificate, cert_pem, logger)

        # Имена файлов на основе CN
        cn = get_cn_from_subject(subject_name)
        safe_name = sanitize_filename(cn)
        cert_filename = f"{safe_name}.cert.pem"
        key_filename = f"{safe_name}.key.pem"

        out_dir.mkdir(parents=True, exist_ok=True)

        # STR-18: создаём каталог ocsp
        ocsp_dir = out_dir.parent / "ocsp"
        ocsp_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Каталог OCSP создан/проверен: %s", ocsp_dir)

        cert_path = out_dir / cert_filename
        cert_path.write_bytes(cert_pem)
        logger.info("Сертификат OCSP-ответчика сохранён: %s", cert_path.resolve())

        # OSC-3: ключ хранится БЕЗ шифрования, права 0o600
        key_path = out_dir / key_filename
        key_pem = serialize_private_key_pem_unencrypted(ocsp_private_key)
        save_key_file(key_pem, key_path)

        # OSC-3: обязательное предупреждение
        logger.warning(
            "ВНИМАНИЕ: Ключ OCSP-ответчика сохранён БЕЗ ШИФРОВАНИЯ в %s. "
            "Права доступа 0o600 установлены. Защитите файл от посторонних.",
            key_path.resolve(),
        )
        print(
            f"\nПРЕДУПРЕЖДЕНИЕ: Ключ OCSP-ответчика сохранён без шифрования!\n"
            f"  Файл: {key_path}\n"
            f"  Это необходимо для автоматического запуска ответчика.\n"
            f"  Убедитесь, что файл доступен только процессу OCSP-ответчика.\n",
            file=sys.stderr,
        )

        serial_hex = serial_to_hex(ocsp_certificate.serial_number)
        logger.info(
            "Аудит: serial=%s, subject=%s, type=ocsp-signing",
            serial_hex, subject,
        )

        print(f"Сертификат OCSP-ответчика: {cert_path}")
        print(f"Ключ OCSP-ответчика:       {key_path}")

    finally:
        if ca_passphrase:
            ba = bytearray(ca_passphrase)
            for i in range(len(ba)):
                ba[i] = 0


def list_certs_cmd(db_path, status, output_format, logger):
    """Вывод списка сертификатов из БД."""
    if not check_schema(db_path):
        logger.error("БД не инициализирована: %s", db_path)
        print("Ошибка: БД не инициализирована. Выполните 'micropki db init'.", file=sys.stderr)
        sys.exit(1)

    certs = list_certificates(db_path, status=status)

    if not certs:
        print("Сертификаты не найдены.")
        return

    if output_format == "json":
        for c in certs:
            c.pop("cert_pem", None)
        print(json.dumps(certs, indent=2, ensure_ascii=False))

    elif output_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["serial_hex", "subject", "not_after", "status"])
        for c in certs:
            writer.writerow([c["serial_hex"], c["subject"], c["not_after"], c["status"]])
        print(output.getvalue())

    else:  # table
        headers = ["Serial", "Subject", "Not After", "Status"]
        rows = []
        for c in certs:
            rows.append([
                c["serial_hex"][:20] + "..." if len(c["serial_hex"]) > 20 else c["serial_hex"],
                c["subject"][:40] + "..." if len(c["subject"]) > 40 else c["subject"],
                c["not_after"][:10],
                c["status"],
            ])

        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(cell))

        fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
        sep = "-+-".join("-" * w for w in col_widths)

        print(fmt.format(*headers))
        print(sep)
        for row in rows:
            print(fmt.format(*row))


def show_cert_cmd(db_path, serial_hex, logger):
    """Вывод PEM конкретного сертификата."""
    if not check_schema(db_path):
        logger.error("БД не инициализирована: %s", db_path)
        print("Ошибка: БД не инициализирована.", file=sys.stderr)
        sys.exit(1)

    if not is_valid_hex(serial_hex):
        logger.error("Некорректный серийный номер: %s", serial_hex)
        print(f"Ошибка: некорректный шестнадцатеричный номер: '{serial_hex}'", file=sys.stderr)
        sys.exit(1)

    logger.info("Получение сертификата: serial=%s", serial_hex)
    cert_data = get_certificate_by_serial(db_path, serial_hex)

    if cert_data is None:
        print(f"Сертификат не найден: {serial_hex}", file=sys.stderr)
        sys.exit(1)

    print(cert_data["cert_pem"])


def main() -> None:
    """Точка входа CLI."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.command == "db":
        if getattr(args, "db_action", None) is None:
            parser.parse_args(["db", "--help"])
            sys.exit(1)

        if args.db_action == "init":
            logger = setup_logger(getattr(args, "log_file", None))
            try:
                init_database(args.db_path)
                print(f"База данных инициализирована: {args.db_path}")
            except Exception as e:
                logger.error("Ошибка инициализации БД: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

    elif args.command == "repo":
        if getattr(args, "repo_action", None) is None:
            parser.parse_args(["repo", "--help"])
            sys.exit(1)

        if args.repo_action == "serve":
            logger = setup_logger(getattr(args, "log_file", None))
            http_log = logging.getLogger("micropki.http")
            if not http_log.handlers:
                for handler in logger.handlers:
                    http_log.addHandler(handler)
                http_log.setLevel(logging.DEBUG)

            try:
                from micropki.server import run_server
                run_server(
                    host=args.host, port=args.port,
                    db_path=str(args.db_path), cert_dir=str(args.cert_dir),
                )
            except Exception as e:
                logger.error("Ошибка сервера: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

    elif args.command == "ocsp":
        if getattr(args, "ocsp_action", None) is None:
            parser.parse_args(["ocsp", "--help"])
            sys.exit(1)

        if args.ocsp_action == "serve":
            logger = setup_logger(getattr(args, "log_file", None))

            # Настраиваем логгеры OCSP
            for log_name in ("micropki.ocsp", "micropki.ocsp.access"):
                ocsp_log = logging.getLogger(log_name)
                if not ocsp_log.handlers:
                    for handler in logger.handlers:
                        ocsp_log.addHandler(handler)
                    ocsp_log.setLevel(logging.DEBUG)

            try:
                from micropki.ocsp_responder import run_ocsp_server
                run_ocsp_server(
                    host=args.host,
                    port=args.port,
                    db_path=str(args.db_path),
                    responder_cert_path=str(args.responder_cert),
                    responder_key_path=str(args.responder_key),
                    ca_cert_path=str(args.ca_cert),
                    cache_ttl=args.cache_ttl,
                    log_file=str(args.log_file) if args.log_file else None,
                )
            except Exception as e:
                logger.error("Ошибка OCSP-ответчика: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

    elif args.command == "ca":
        if getattr(args, "ca_action", None) is None:
            parser.parse_args(["ca", "--help"])
            sys.exit(1)

        logger = setup_logger(getattr(args, "log_file", None))

        if args.ca_action == "init":
            errors = validate_init_args(args)
            if errors:
                for err in errors:
                    logger.error("Ошибка валидации: %s", err)
                    print(f"Ошибка: {err}", file=sys.stderr)
                sys.exit(1)
            try:
                init_root_ca(
                    subject=args.subject, key_type=args.key_type,
                    key_size=args.key_size, passphrase_file=args.passphrase_file,
                    out_dir=args.out_dir, validity_days=args.validity_days,
                    force=args.force, logger=logger,
                    db_path=getattr(args, "db_path", None),
                )
            except SystemExit:
                raise
            except Exception as e:
                logger.error("Ошибка: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.ca_action == "issue-intermediate":
            errors = validate_intermediate_args(args)
            if errors:
                for err in errors:
                    logger.error("Ошибка валидации: %s", err)
                    print(f"Ошибка: {err}", file=sys.stderr)
                sys.exit(1)
            try:
                issue_intermediate(
                    root_cert_path=args.root_cert, root_key_path=args.root_key,
                    root_pass_file=args.root_pass_file, subject=args.subject,
                    key_type=args.key_type, key_size=args.key_size,
                    passphrase_file=args.passphrase_file, out_dir=args.out_dir,
                    validity_days=args.validity_days, path_length=args.pathlen,
                    force=args.force, logger=logger, db_path=args.db_path,
                )
            except SystemExit:
                raise
            except Exception as e:
                logger.error("Ошибка: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.ca_action == "issue-cert":
            errors = validate_issue_cert_args(args)
            if errors:
                for err in errors:
                    logger.error("Ошибка валидации: %s", err)
                    print(f"Ошибка: {err}", file=sys.stderr)
                sys.exit(1)
            try:
                issue_leaf_cert(
                    ca_cert_path=args.ca_cert, ca_key_path=args.ca_key,
                    ca_pass_file=args.ca_pass_file, template_name=args.template,
                    subject=args.subject, san_strings=args.san,
                    key_type=args.key_type, key_size=args.key_size,
                    out_dir=args.out_dir, validity_days=args.validity_days,
                    logger=logger, db_path=args.db_path,
                )
            except SystemExit:
                raise
            except Exception as e:
                logger.error("Ошибка: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.ca_action == "issue-ocsp-cert":
            if args.key_size is None:
                args.key_size = 2048 if args.key_type == "rsa" else 256

            errors = []
            if not args.subject or not args.subject.strip():
                errors.append("--subject должен быть непустой строкой.")
            errors.extend(_validate_file_exists(args.ca_cert, "--ca-cert"))
            errors.extend(_validate_file_exists(args.ca_key, "--ca-key"))
            errors.extend(_validate_passphrase_file(args.ca_pass_file))
            errors.extend(_validate_positive_int(args.validity_days, "--validity-days"))
            errors.extend(_validate_out_dir(args.out_dir))
            if args.key_type == "rsa" and args.key_size < 2048:
                errors.append("RSA ключ для OCSP должен быть >= 2048 бит.")
            if args.key_type == "ecc" and args.key_size < 256:
                errors.append("ECC ключ для OCSP должен быть >= 256 бит.")

            if errors:
                for err in errors:
                    logger.error("Ошибка валидации: %s", err)
                    print(f"Ошибка: {err}", file=sys.stderr)
                sys.exit(1)

            try:
                issue_ocsp_cert(
                    ca_cert_path=args.ca_cert,
                    ca_key_path=args.ca_key,
                    ca_pass_file=args.ca_pass_file,
                    subject=args.subject,
                    san_strings=args.san,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    logger=logger,
                    db_path=args.db_path,
                )
            except SystemExit:
                raise
            except Exception as e:
                logger.error("Ошибка выпуска OCSP-сертификата: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.ca_action == "list-certs":
            list_certs_cmd(args.db_path, args.status, args.output_format, logger)

        elif args.ca_action == "show-cert":
            show_cert_cmd(args.db_path, args.serial, logger)

        elif args.ca_action == "revoke":
            from micropki.revocation import revoke_certificate, validate_reason
            from micropki.database import check_schema as check_db

            if not check_db(args.db_path):
                logger.error("БД не инициализирована: %s", args.db_path)
                print("Ошибка: БД не инициализирована.", file=sys.stderr)
                sys.exit(1)

            try:
                validate_reason(args.reason)
            except ValueError as e:
                logger.error("Ошибка валидации: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)

            if not args.force:
                answer = input(
                    f"Вы уверены, что хотите отозвать сертификат {args.serial}? [y/N]: "
                )
                if answer.lower() not in ("y", "yes", "д", "да"):
                    print("Отмена.")
                    sys.exit(0)

            result = revoke_certificate(
                db_path=args.db_path,
                serial_hex=args.serial,
                reason=args.reason,
                logger_inst=logger,
            )

            print(result["message"])

            if result["status"] == "not_found":
                sys.exit(1)
            else:
                sys.exit(0)

        elif args.ca_action == "gen-crl":
            from micropki.crl import generate_crl
            from micropki.crypto_utils import load_encrypted_private_key, load_certificate, read_passphrase
            from micropki.database import check_schema as check_db

            if not check_db(args.db_path):
                logger.error("БД не инициализирована: %s", args.db_path)
                print("Ошибка: БД не инициализирована.", file=sys.stderr)
                sys.exit(1)

            try:
                passphrase = read_passphrase(args.ca_pass_file)
                ca_cert = load_certificate(args.ca_cert)
                ca_key = load_encrypted_private_key(args.ca_key, passphrase)

                crl_path = generate_crl(
                    ca_name=args.ca,
                    ca_cert=ca_cert,
                    ca_private_key=ca_key,
                    db_path=args.db_path,
                    out_dir=args.out_dir,
                    next_update_days=args.next_update,
                    out_file=args.out_file,
                    logger_inst=logger,
                )

                print(f"CRL сгенерирован: {crl_path}")

                ba = bytearray(passphrase)
                for i in range(len(ba)):
                    ba[i] = 0

            except Exception as e:
                logger.error("Ошибка генерации CRL: %s", e)
                print(f"Ошибка: {e}", file=sys.stderr)
                sys.exit(1)