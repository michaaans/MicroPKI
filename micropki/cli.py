"""
Парсер аргументов командной строки для MicroPKI.

Подкоманды:
  ca init               — создать корневой CA
  ca issue-intermediate — создать промежуточный CA
  ca issue-cert         — выпустить конечный сертификат (поддерживает --csr)
  ca issue-ocsp-cert    — выпустить сертификат OCSP-ответчика
  ca list-certs         — список сертификатов
  ca show-cert          — показать конкретный сертификат
  ca revoke             — отозвать сертификат
  ca gen-crl            — сгенерировать CRL
  db init               — инициализировать БД
  repo serve            — запустить HTTP-сервер репозитория
  ocsp serve            — запустить OCSP-ответчик
  client gen-csr        — сгенерировать закрытый ключ и CSR
  client request-cert   — запросить сертификат у CA через API
  client validate       — проверить цепочку сертификатов
  client check-status   — проверить статус отзыва
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
        metavar="[ca, db, repo, ocsp, client]",
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
    ca_issue.add_argument("--subject", required=False, default=None, type=str,
                          help="DN субъекта. Если указан --csr, берётся из CSR.")
    ca_issue.add_argument("--san", action="append", default=[])
    ca_issue.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_issue.add_argument("--key-size", default=None, type=int)
    ca_issue.add_argument("--out-dir", default=Path("./pki/certs"), type=Path)
    ca_issue.add_argument("--validity-days", default=365, type=int)
    ca_issue.add_argument("--log-file", default=None, type=Path)
    ca_issue.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    # CLI-29 / CA-1: поддержка внешнего CSR
    ca_issue.add_argument(
        "--csr", default=None, type=Path,
        help=(
            "Путь к внешнему CSR (PEM). Если указан: субъект и SAN берутся "
            "из CSR, новый ключ НЕ генерируется."
        ),
    )

    # --- ca issue-ocsp-cert ---
    ca_ocsp = ca_sub.add_parser(
        "issue-ocsp-cert",
        help="Выпустить сертификат OCSP-ответчика",
    )
    ca_ocsp.add_argument("--ca-cert", required=True, type=Path)
    ca_ocsp.add_argument("--ca-key", required=True, type=Path)
    ca_ocsp.add_argument("--ca-pass-file", required=True, type=Path)
    ca_ocsp.add_argument("--subject", required=True, type=str)
    ca_ocsp.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_ocsp.add_argument("--key-size", default=None, type=int)
    ca_ocsp.add_argument("--san", action="append", default=[])
    ca_ocsp.add_argument("--out-dir", default=Path("./pki/certs"), type=Path)
    ca_ocsp.add_argument("--validity-days", default=365, type=int)
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
        help="Причина отзыва (по умолчанию: unspecified).",
    )
    ca_revoke.add_argument("--force", action="store_true", default=False)
    ca_revoke.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_revoke.add_argument("--log-file", default=None, type=Path)

    # --- ca gen-crl ---
    ca_gencrl = ca_sub.add_parser("gen-crl", help="Сгенерировать CRL")
    ca_gencrl.add_argument("--ca", required=True)
    ca_gencrl.add_argument("--ca-cert", required=True, type=Path)
    ca_gencrl.add_argument("--ca-key", required=True, type=Path)
    ca_gencrl.add_argument("--ca-pass-file", required=True, type=Path)
    ca_gencrl.add_argument("--next-update", default=7, type=int)
    ca_gencrl.add_argument("--out-file", default=None, type=Path)
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
        dest="ocsp_action", title="ocsp actions", metavar="<action>",
    )
    ocsp_serve = ocsp_sub.add_parser("serve", help="Запустить OCSP-ответчик")
    ocsp_serve.add_argument("--host", default="127.0.0.1")
    ocsp_serve.add_argument("--port", default=8081, type=int)
    ocsp_serve.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ocsp_serve.add_argument("--responder-cert", required=True, type=Path)
    ocsp_serve.add_argument("--responder-key", required=True, type=Path)
    ocsp_serve.add_argument("--ca-cert", required=True, type=Path)
    ocsp_serve.add_argument("--cache-ttl", default=60, type=int)
    ocsp_serve.add_argument("--log-file", default=None, type=Path)

    # ==================== client ====================
    client_parser = top_sub.add_parser(
        "client", help="Клиентские операции (CSR, проверка цепочки, отзыв)"
    )
    client_sub = client_parser.add_subparsers(
        dest="client_action",
        title="client actions",
        metavar="<action>",
    )

    # --- client gen-csr ---
    c_gencsr = client_sub.add_parser(
        "gen-csr",
        help="Сгенерировать закрытый ключ и CSR (CLI-25)",
    )
    c_gencsr.add_argument("--subject", required=True, type=str,
                          help="DN субъекта (например: CN=app.example.com)")
    c_gencsr.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    c_gencsr.add_argument("--key-size", default=None, type=int,
                          help="Размер ключа (RSA: 2048/4096, ECC: 256/384)")
    c_gencsr.add_argument("--san", action="append", default=[],
                          help="SAN в формате тип:значение (можно повторять)")
    c_gencsr.add_argument("--out-key", default=Path("./key.pem"), type=Path,
                          help="Файл для закрытого ключа (по умолч.: ./key.pem)")
    c_gencsr.add_argument("--out-csr", default=Path("./request.csr.pem"), type=Path,
                          help="Файл для CSR (по умолч.: ./request.csr.pem)")
    c_gencsr.add_argument("--log-file", default=None, type=Path)

    # --- client request-cert ---
    c_reqcert = client_sub.add_parser(
        "request-cert",
        help="Отправить CSR в CA и получить сертификат (CLI-26)",
    )
    c_reqcert.add_argument("--csr", required=True, type=Path,
                           help="Путь к файлу CSR (PEM)")
    c_reqcert.add_argument("--template", required=True,
                           choices=["server", "client", "code_signing"])
    c_reqcert.add_argument("--ca-url", required=True, type=str,
                           help="Базовый URL репозитория (например: http://localhost:8080)")
    c_reqcert.add_argument("--out-cert", default=Path("./cert.pem"), type=Path,
                           help="Файл для сохранения сертификата (по умолч.: ./cert.pem)")
    c_reqcert.add_argument("--api-key", default=None, type=str,
                           help="API-ключ (X-API-Key заголовок)")
    c_reqcert.add_argument("--log-file", default=None, type=Path)

    # --- client validate ---
    c_validate = client_sub.add_parser(
        "validate",
        help="Проверить цепочку сертификатов (CLI-27)",
    )
    c_validate.add_argument("--cert", required=True, type=Path,
                            help="Конечный сертификат (PEM)")
    c_validate.add_argument("--untrusted", action="append", default=[], type=Path,
                            help="Промежуточные сертификаты (PEM, можно повторять)")
    c_validate.add_argument(
        "--trusted", default=Path("./pki/certs/ca.cert.pem"), type=Path,
        help="Доверенные корневые сертификаты (PEM-набор)",
    )
    c_validate.add_argument("--crl", default=None, type=str,
                            help="CRL: локальный файл или URL")
    c_validate.add_argument("--ocsp", default=None, type=str,
                            dest="ocsp_url",
                            help="URL OCSP-ответчика (или пустая строка для авто из AIA)")
    c_validate.add_argument(
        "--mode", choices=["chain", "full"], default="full",
        help="chain=только цепочка, full=цепочка+отзыв (по умолч.: full)",
    )
    c_validate.add_argument(
        "--validation-time", default=None, type=str,
        help=(
            "Время для проверки срока действия "
            "(ISO 8601, например: 2025-01-01T00:00:00Z)"
        ),
    )
    c_validate.add_argument("--log-file", default=None, type=Path)

    # --- client check-status ---
    c_checkstatus = client_sub.add_parser(
        "check-status",
        help="Проверить статус отзыва сертификата (CLI-28)",
    )
    c_checkstatus.add_argument("--cert", required=True, type=Path,
                               help="Сертификат для проверки (PEM)")
    c_checkstatus.add_argument("--ca-cert", required=True, type=Path,
                               help="Сертификат издателя (PEM)")
    c_checkstatus.add_argument("--crl", default=None, type=str,
                               help="Файл CRL или URL (опционально)")
    c_checkstatus.add_argument("--ocsp-url", default=None, type=str,
                               help="URL OCSP-ответчика (опционально, иначе из AIA)")
    c_checkstatus.add_argument("--log-file", default=None, type=Path)

    return root