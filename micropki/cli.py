"""
Парсер аргументов командной строки для MicroPKI.

Подкоманды:
  ca init               — создать корневой CA
  ca issue-intermediate — создать промежуточный CA
  ca issue-cert         — выпустить конечный сертификат
  ca issue-ocsp-cert    — выпустить сертификат OCSP-ответчика
  ca list-certs         — список сертификатов
  ca show-cert          — показать конкретный сертификат
  ca revoke             — отозвать сертификат
  ca gen-crl            — сгенерировать CRL
  db init               — инициализировать БД
  repo serve            — запустить HTTP-сервер репозитория
  ocsp serve            — запустить OCSP-ответчик
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

    root.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Путь к файлу конфигурации (по умолчанию: micropki.conf)",
    )

    top_sub = root.add_subparsers(
        dest="command",
        title="commands",
        metavar="[ca, db, repo, ocsp]",
    )

    # ==================== ca ====================
    ca_parser = top_sub.add_parser("ca",
                                   help="Операции с удостоверяющим центром")
    ca_sub = ca_parser.add_subparsers(
        dest="ca_action",
        title="ca actions",
        metavar="<action>")

    # --- ca init ---
    ca_init = ca_sub.add_parser("init",
                                help="Создать самоподписанный корневой УЦ")
    ca_init.add_argument("--subject", "-sub", required=True, type=str)
    ca_init.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_init.add_argument("--key-size", choices=[4096, 384], default=None, type=int)
    ca_init.add_argument("--passphrase-file", required=True, type=Path)
    ca_init.add_argument("--out-dir", default=Path("./pki"), type=Path)
    ca_init.add_argument("--validity-days", default=3650, type=int)
    ca_init.add_argument("--log-file", default=None, type=Path)
    ca_init.add_argument("--force", action="store_true", default=False)
    ca_init.add_argument("--db-path", default=None, type=Path,
                         help="Путь к БД (если указан — вставить корневой CA в БД)")

    # --- ca issue-intermediate ---
    ca_inter = ca_sub.add_parser("issue-intermediate",
                                 help="Создать промежуточный УЦ")
    ca_inter.add_argument("--root-cert", required=True, type=Path)
    ca_inter.add_argument("--root-key", required=True, type=Path)
    ca_inter.add_argument("--root-pass-file", required=True, type=Path)
    ca_inter.add_argument("--subject", required=True, type=str)
    ca_inter.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_inter.add_argument("--key-size", choices=[4096, 384], default=None, type=int)
    ca_inter.add_argument("--passphrase-file", required=True, type=Path)
    ca_inter.add_argument("--out-dir", default=Path("./pki"), type=Path)
    ca_inter.add_argument("--validity-days", default=1825, type=int)
    ca_inter.add_argument("--pathlen", default=0, type=int)
    ca_inter.add_argument("--log-file", default=None, type=Path)
    ca_inter.add_argument("--force", action="store_true", default=False)
    ca_inter.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)

    # --- ca issue-cert ---
    ca_issue = ca_sub.add_parser("issue-cert",
                                 help="Выпустить конечный сертификат")
    ca_issue.add_argument("--ca-cert", required=True, type=Path)
    ca_issue.add_argument("--ca-key", required=True, type=Path)
    ca_issue.add_argument("--ca-pass-file", required=True, type=Path)
    ca_issue.add_argument("--template", required=True,
                          choices=["server", "client", "code_signing"])
    ca_issue.add_argument("--subject", required=True, type=str)
    ca_issue.add_argument("--san", action="append", default=[])
    ca_issue.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_issue.add_argument("--key-size", default=None, type=int)
    ca_issue.add_argument("--out-dir", default=Path("./pki/certs"), type=Path)
    ca_issue.add_argument("--validity-days", default=365, type=int)
    ca_issue.add_argument("--log-file", default=None, type=Path)
    ca_issue.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)

    # --- ca issue-ocsp-cert ---
    ca_ocsp = ca_sub.add_parser(
        "issue-ocsp-cert",
        help="Выпустить сертификат OCSP-ответчика",
    )
    ca_ocsp.add_argument("--ca-cert", required=True, type=Path,
                         help="Сертификат промежуточного УЦ (PEM)")
    ca_ocsp.add_argument("--ca-key", required=True, type=Path,
                         help="Закрытый ключ промежуточного УЦ (PEM)")
    ca_ocsp.add_argument("--ca-pass-file", required=True, type=Path,
                         help="Парольная фраза для ключа УЦ")
    ca_ocsp.add_argument("--subject", required=True, type=str,
                         help="DN субъекта (например: CN=OCSP Responder,O=MicroPKI)")
    ca_ocsp.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa",
                         help="Тип ключа (по умолчанию: rsa)")
    ca_ocsp.add_argument("--key-size", default=None, type=int,
                         help="Размер ключа (RSA >= 2048, ECC >= 256)")
    ca_ocsp.add_argument("--san", action="append", default=[],
                         help="SAN (dns:ocsp.example.com или uri:http://ocsp.example.com/)")
    ca_ocsp.add_argument("--out-dir", default=Path("./pki/certs"), type=Path,
                         help="Выходной каталог (по умолчанию: ./pki/certs)")
    ca_ocsp.add_argument("--validity-days", default=365, type=int,
                         help="Срок действия в днях (по умолчанию: 365)")
    ca_ocsp.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_ocsp.add_argument("--log-file", default=None, type=Path)

    # --- ca list-certs ---
    ca_list = ca_sub.add_parser("list-certs",
                                help="Список выпущенных сертификатов")
    ca_list.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    ca_list.add_argument("--format", dest="output_format",
                         choices=["table", "json", "csv"], default="table")
    ca_list.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_list.add_argument("--log-file", default=None, type=Path)

    # --- ca show-cert ---
    ca_show = ca_sub.add_parser("show-cert",
                                help="Показать сертификат по серийному номеру")
    ca_show.add_argument("serial", type=str, help="Серийный номер в hex")
    ca_show.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_show.add_argument("--log-file", default=None, type=Path)

    # --- ca revoke ---
    ca_revoke = ca_sub.add_parser("revoke", help="Отозвать сертификат")
    ca_revoke.add_argument("serial", type=str, help="Серийный номер в hex")
    ca_revoke.add_argument(
        "--reason", default="unspecified",
        help="Причина отзыва (по умолчанию: unspecified). "
             "Допустимые: keyCompromise, cACompromise, affiliationChanged, "
             "superseded, cessationOfOperation, certificateHold, "
             "removeFromCRL, privilegeWithdrawn, aACompromise",
    )
    ca_revoke.add_argument("--force", action="store_true", default=False,
                           help="Без запроса подтверждения")
    ca_revoke.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_revoke.add_argument("--log-file", default=None, type=Path)

    # --- ca gen-crl ---
    ca_gencrl = ca_sub.add_parser("gen-crl", help="Сгенерировать CRL")
    ca_gencrl.add_argument("--ca", required=True,
                           help="Имя CA: 'root' или 'intermediate'")
    ca_gencrl.add_argument("--ca-cert", required=True, type=Path,
                           help="Путь к сертификату CA")
    ca_gencrl.add_argument("--ca-key", required=True, type=Path,
                           help="Путь к закрытому ключу CA")
    ca_gencrl.add_argument("--ca-pass-file", required=True, type=Path,
                           help="Парольная фраза для ключа CA")
    ca_gencrl.add_argument("--next-update", default=7, type=int,
                           help="Дней до следующего обновления CRL (по умолчанию: 7)")
    ca_gencrl.add_argument("--out-file", default=None, type=Path,
                           help="Путь к выходному файлу CRL")
    ca_gencrl.add_argument("--out-dir", default=Path("./pki"), type=Path)
    ca_gencrl.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_gencrl.add_argument("--log-file", default=None, type=Path)

    # ==================== db ====================
    db_parser = top_sub.add_parser("db", help="Управление базой данных")
    db_sub = db_parser.add_subparsers(dest="db_action",
                                      title="db actions",
                                      metavar="<action>")

    db_init = db_sub.add_parser("init", help="Инициализировать базу данных")
    db_init.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    db_init.add_argument("--log-file", default=None, type=Path)

    # ==================== repo ====================
    repo_parser = top_sub.add_parser("repo", help="Управление репозиторием")
    repo_sub = repo_parser.add_subparsers(dest="repo_action",
                                          title="repo actions",
                                          metavar="<action>")

    repo_serve = repo_sub.add_parser("serve", help="Запустить HTTP-сервер репозитория")
    repo_serve.add_argument("--host", default="127.0.0.1")
    repo_serve.add_argument("--port", default=8080, type=int)
    repo_serve.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    repo_serve.add_argument("--cert-dir", default=Path("./pki/certs"), type=Path)
    repo_serve.add_argument("--log-file", default=None, type=Path)

    # ==================== ocsp ====================
    ocsp_parser = top_sub.add_parser("ocsp", help="Управление OCSP-ответчиком")
    ocsp_sub = ocsp_parser.add_subparsers(
        dest="ocsp_action",
        title="ocsp actions",
        metavar="<action>",
    )

    ocsp_serve = ocsp_sub.add_parser("serve", help="Запустить OCSP-ответчик")
    ocsp_serve.add_argument("--host", default="127.0.0.1",
                            help="Адрес привязки (по умолчанию: 127.0.0.1)")
    ocsp_serve.add_argument("--port", default=8081, type=int,
                            help="TCP-порт (по умолчанию: 8081)")
    ocsp_serve.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path,
                            help="Путь к БД SQLite")
    ocsp_serve.add_argument("--responder-cert", required=True, type=Path,
                            help="Сертификат подписи OCSP (PEM)")
    ocsp_serve.add_argument("--responder-key", required=True, type=Path,
                            help="Закрытый ключ OCSP-ответчика (PEM, без шифрования)")
    ocsp_serve.add_argument("--ca-cert", required=True, type=Path,
                            help="Сертификат выпускающего УЦ (PEM)")
    ocsp_serve.add_argument("--cache-ttl", default=60, type=int,
                            help="TTL кэша ответов в секундах (по умолчанию: 60)")
    ocsp_serve.add_argument("--log-file", default=None, type=Path,
                            help="Файл журнала (по умолчанию: stderr)")

    return root