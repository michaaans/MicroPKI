"""
Парсер аргументов командной строки для MicroPKI.

Поддерживает подкоманду  ca init.
Парсер расширяем — новые подкоманды добавляются в ca_sub.
"""

import argparse
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
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

    # ==================== Подкоманда ca init ====================

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
        help="Путь к файлу с парольной фразой для шифрования закрытого ключа",
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

    return root