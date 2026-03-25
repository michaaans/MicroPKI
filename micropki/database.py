"""
Модуль работы с базой данных SQLite.

Содержит:
- инициализацию БД и создание схемы
- получение подключения
- создание индексов
"""

import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger("micropki")

SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_subject ON certificates(subject);
"""

# Версия схемы для поддержки миграций
SCHEMA_VERSION = 1

MIGRATION_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"""


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """
    Открывает подключение к SQLite.

    Включает поддержку внешних ключей и WAL-режим
    для лучшей производительности при параллельных чтениях.

    :param db_path: путь к файлу БД
    :return: объект подключения
    """
    db_path = str(db_path)
    conn = sqlite3.Connection(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_database(db_path: str | Path) -> None:
    """
    Инициализирует базу данных: создаёт таблицы и индексы.

    :param db_path: путь к файлу БД
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        )
        table_exists = cursor.fetchone() is not None

        if table_exists:
            logger.info("База данных уже инициализирована: %s", db_path)
            return

        # Создаём схему
        conn.executescript(SCHEMA_SQL)

        # Создаём таблицу версии схемы
        conn.executescript(MIGRATION_TABLE_SQL)
        cursor.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            (SCHEMA_VERSION,),
        )
        conn.commit()

        logger.info(
            "База данных инициализирована: %s (версия схемы: %d)",
            db_path, SCHEMA_VERSION,
        )

    except sqlite3.Error as e:
        logger.error("Ошибка инициализации БД: %s", e)
        raise
    finally:
        conn.close()


def check_schema(db_path: str | Path) -> bool:
    """
    Проверяет, что схема БД инициализирована.

    :param db_path: путь к файлу БД
    :return: True если таблица certificates существует
    """
    db_path = Path(db_path)
    if not db_path.exists():
        return False

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        )
        return cursor.fetchone() is not None
    finally:
        conn.close()