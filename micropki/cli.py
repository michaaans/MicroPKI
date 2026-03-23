"""
Парсер аргументов командной строки для MicroPKI.

Поддерживает подкоманды:
  ca init               — создать корневой CA (Спринт 1)
  ca issue-intermediate — создать промежуточный CA (Спринт 2)
  ca issue-cert         — выпустить конечный сертификат (Спринт 2)
"""

import argparse
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
    """
    Создание парсера аргументов командной строки для MicroPKI.

    :return: настроенный парсер аргументов
    """
    root = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI — учебный УЦ",
    )

    top_sub = root.add_subparsers(
        dest="command",
        title="commands",
        metavar="[ca, ...]",
    )

    # ==================== Подкоманда ca ====================

    ca_parser = top_sub.add_parser(
        "ca",
        help="Операции с удостоверяющим центром",
    )

    ca_sub = ca_parser.add_subparsers(
        dest="ca_action",
        title="ca actions",
        metavar="<action>",
    )

    # ==================== ca init ====================

    ca_init = ca_sub.add_parser(
        "init",
        help="Создать самоподписанный корневой УЦ",
    )

    ca_init.add_argument(
        "--subject", "-sub",
        required=True,
        type=str,
        help='Отличительное имя (DN), например "/CN=My Root CA"',
    )
    ca_init.add_argument(
        "--key-type",
        choices=["rsa", "ecc"],
        default="rsa",
        help="Тип ключа (по умолчанию: rsa)",
    )
    ca_init.add_argument(
        "--key-size",
        choices=[4096, 384],
        default=None,
        type=int,
        help="Размер ключа в битах (4096 для RSA, 384 для ECC)",
    )
    ca_init.add_argument(
        "--passphrase-file",
        required=True,
        type=Path,
        help="Путь к файлу с парольной фразой",
    )
    ca_init.add_argument(
        "--out-dir",
        default=Path("./pki"),
        type=Path,
        help="Выходной каталог (по умолчанию: ./pki)",
    )
    ca_init.add_argument(
        "--validity-days",
        default=3650,
        type=int,
        help="Срок действия в днях (по умолчанию: 3650)",
    )
    ca_init.add_argument(
        "--log-file",
        default=None,
        type=Path,
        help="Путь к файлу журнала (если не указан — stderr)",
    )
    ca_init.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Перезаписать существующие файлы без подтверждения",
    )

    # ==================== ca issue-intermediate ====================

    ca_intermediate = ca_sub.add_parser(
        "issue-intermediate",
        help="Создать промежуточный УЦ, подписанный корневым",
    )

    ca_intermediate.add_argument(
        "--root-cert",
        required=True,
        type=Path,
        help="Путь к сертификату корневого УЦ (PEM)",
    )
    ca_intermediate.add_argument(
        "--root-key",
        required=True,
        type=Path,
        help="Путь к зашифрованному закрытому ключу корневого УЦ (PEM)",
    )
    ca_intermediate.add_argument(
        "--root-pass-file",
        required=True,
        type=Path,
        help="Файл с парольной фразой для ключа корневого УЦ",
    )
    ca_intermediate.add_argument(
        "--subject",
        required=True,
        type=str,
        help='DN для промежуточного УЦ, например "CN=Intermediate CA,O=MicroPKI"',
    )
    ca_intermediate.add_argument(
        "--key-type",
        choices=["rsa", "ecc"],
        default="rsa",
        help="Тип ключа (по умолчанию: rsa)",
    )
    ca_intermediate.add_argument(
        "--key-size",
        choices=[4096, 384],
        default=None,
        type=int,
        help="Размер ключа (4096 для RSA, 384 для ECC)",
    )
    ca_intermediate.add_argument(
        "--passphrase-file",
        required=True,
        type=Path,
        help="Парольная фраза для ключа промежуточного УЦ",
    )
    ca_intermediate.add_argument(
        "--out-dir",
        default=Path("./pki"),
        type=Path,
        help="Выходной каталог (по умолчанию: ./pki)",
    )
    ca_intermediate.add_argument(
        "--validity-days",
        default=1825,
        type=int,
        help="Срок действия (по умолчанию: 1825 ≈ 5 лет)",
    )
    ca_intermediate.add_argument(
        "--pathlen",
        default=0,
        type=int,
        help="Ограничение длины пути (по умолчанию: 0)",
    )
    ca_intermediate.add_argument(
        "--log-file",
        default=None,
        type=Path,
        help="Путь к файлу журнала",
    )
    ca_intermediate.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Перезаписать существующие файлы",
    )

    # ==================== ca issue-cert ====================

    ca_issue = ca_sub.add_parser(
        "issue-cert",
        help="Выпустить конечный сертификат",
    )

    ca_issue.add_argument(
        "--ca-cert",
        required=True,
        type=Path,
        help="Сертификат промежуточного УЦ (PEM)",
    )
    ca_issue.add_argument(
        "--ca-key",
        required=True,
        type=Path,
        help="Зашифрованный закрытый ключ промежуточного УЦ (PEM)",
    )
    ca_issue.add_argument(
        "--ca-pass-file",
        required=True,
        type=Path,
        help="Парольная фраза для ключа промежуточного УЦ",
    )
    ca_issue.add_argument(
        "--template",
        required=True,
        choices=["server", "client", "code_signing"],
        help="Шаблон сертификата: server, client, code_signing",
    )
    ca_issue.add_argument(
        "--subject",
        required=True,
        type=str,
        help='DN для сертификата, например "CN=example.com,O=MicroPKI"',
    )
    ca_issue.add_argument(
        "--san",
        action="append",
        default=[],
        help="SAN запись (можно указать несколько раз): dns:example.com, ip:1.2.3.4, email:a@b.com",
    )
    ca_issue.add_argument(
        "--key-type",
        choices=["rsa", "ecc"],
        default="rsa",
        help="Тип ключа конечного субъекта (по умолчанию: rsa)",
    )
    ca_issue.add_argument(
        "--key-size",
        default=None,
        type=int,
        help="Размер ключа (по умолчанию: 2048 для RSA, 256 для ECC)",
    )
    ca_issue.add_argument(
        "--out-dir",
        default=Path("./pki/certs"),
        type=Path,
        help="Выходной каталог (по умолчанию: ./pki/certs)",
    )
    ca_issue.add_argument(
        "--validity-days",
        default=365,
        type=int,
        help="Срок действия (по умолчанию: 365)",
    )
    ca_issue.add_argument(
        "--log-file",
        default=None,
        type=Path,
        help="Путь к файлу журнала",
    )

    return root