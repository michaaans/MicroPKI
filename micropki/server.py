"""
HTTP-сервер репозитория сертификатов (FastAPI).

Эндпоинты:
  GET /certificate/{serial_hex} — получить сертификат по серийному номеру
  GET /ca/{level}               — получить сертификат УЦ (root / intermediate)
  GET /crl                      — заглушка для CRL (501)
"""

import os
import logging
import signal
from pathlib import Path
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from micropki.database import check_schema
from micropki.repository import get_certificate_by_serial
from micropki.serial import is_valid_hex

logger = logging.getLogger("micropki")
http_logger = logging.getLogger("micropki.http")


def create_app(db_path: str, cert_dir: str) -> FastAPI:
    """
    Создаёт экземпляр FastAPI-приложения.

    :param db_path: путь к базе данных SQLite
    :param cert_dir: каталог с PEM-сертификатами
    :return: экземпляр FastAPI
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Управление жизненным циклом приложения."""
        logger.info(
            "Сервер репозитория запущен (db=%s, certs=%s)", db_path, cert_dir
        )
        yield
        logger.info("Сервер репозитория остановлен")

    app = FastAPI(
        title="MicroPKI Repository",
        description="Репозиторий сертификатов MicroPKI",
        lifespan=lifespan,
    )

    # CORS-заголовки (REPO-7)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    # Сохраняем параметры в state приложения
    app.state.db_path = db_path
    app.state.cert_dir = cert_dir

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        """Логирование каждого HTTP-запроса."""
        response = await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        http_logger.info(
            "[HTTP] %s %s %s → %d",
            request.method,
            request.url.path,
            client_ip,
            response.status_code,
        )
        return response

    @app.get("/certificate/{serial_hex}")
    async def get_certificate(serial_hex: str):
        """
        Получить сертификат по серийному номеру.

        :param serial_hex: серийный номер в hex (регистронезависимо)
        :return: PEM-сертификат
        """
        # Валидация формата (REPO-8, TEST-19)
        if not is_valid_hex(serial_hex):
            raise HTTPException(
                status_code=400,
                detail=f"Некорректный формат серийного номера: '{serial_hex}'. "
                       f"Ожидается шестнадцатеричная строка.",
            )

        cert_data = get_certificate_by_serial(db_path, serial_hex)
        if cert_data is None:
            raise HTTPException(
                status_code=404,
                detail=f"Сертификат не найден: {serial_hex}",
            )

        return PlainTextResponse(
            content=cert_data["cert_pem"],
            media_type="application/x-pem-file",
        )

    @app.get("/ca/{level}")
    async def get_ca_certificate(level: str):
        """
        Получить сертификат УЦ.

        :param level: 'root' или 'intermediate'
        :return: PEM-сертификат
        """
        # Маппинг уровня → имя файла
        file_map = {
            "root": "ca.cert.pem",
            "intermediate": "intermediate.cert.pem",
        }

        if level not in file_map:
            raise HTTPException(
                status_code=400,
                detail=f"Неподдерживаемый уровень УЦ: '{level}'. "
                       f"Допустимые: root, intermediate.",
            )

        cert_path = Path(cert_dir) / file_map[level]
        if not cert_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Сертификат УЦ не найден: {cert_path}",
            )

        pem_content = cert_path.read_text(encoding="utf-8")
        return PlainTextResponse(
            content=pem_content,
            media_type="application/x-pem-file",
        )

    @app.get("/crl")
    async def get_crl():
        """
        Получить список отзыва сертификатов (CRL).
        Заглушка для Спринта 4.
        """
        return PlainTextResponse(
            content="Генерация CRL ещё не реализована",
            status_code=501,
            media_type="application/pkix-crl",
        )

    return app


def run_server(
    host: str,
    port: int,
    db_path: str,
    cert_dir: str,
) -> None:
    """
    Запускает HTTP-сервер репозитория.

    :param host: адрес привязки
    :param port: TCP-порт
    :param db_path: путь к БД
    :param cert_dir: каталог с сертификатами
    """
    if not check_schema(db_path):
        logger.error(
            "База данных не инициализирована: %s. "
            "Выполните 'micropki db init' сначала.",
            db_path,
        )
        raise RuntimeError("База данных не инициализирована")

    app = create_app(db_path, cert_dir)

    logger.info("Запуск сервера на http://%s:%d", host, port)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
