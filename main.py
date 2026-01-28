# main.py
import asyncio
import logging
import os
import signal
import sys
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

from config import settings
from handlers.common import router as common_router
from handlers.scan_domain import router as scan_router
from handlers.phone_scan import router as phone_router
from handlers.bin_scan import router as bin_router
from handlers.url_scan import router as url_router
from handlers.email_scan import router as email_router
from handlers.ip_scan import router as ip_router
from handlers.username_scan import router as username_router
from handlers.wallet_scan import router as wallet_router
from handlers.leak_scan import router as leak_router
from handlers.exif_scan import router as exif_router
from handlers.auto_detect import router as auto_detect_router
from middlewares.logging import LoggingMiddleware
from middlewares.rate_limit import RateLimitMiddleware

log = logging.getLogger(__name__)

# Глобальные переменные для graceful shutdown
_bot: Optional[Bot] = None
_dp: Optional[Dispatcher] = None
_shutdown_event: Optional[asyncio.Event] = None


def _setup_logging() -> None:
    """Настройка логирования."""
    os.makedirs("logs", exist_ok=True)

    log_format = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("logs/app.log", encoding="utf-8"),
        ],
    )


def _handle_signal(signum: int, frame) -> None:
    """Обработчик сигналов для graceful shutdown."""
    sig_name = signal.Signals(signum).name
    log.info(f"Received signal {sig_name}, initiating graceful shutdown...")

    if _shutdown_event:
        _shutdown_event.set()


async def _shutdown(bot: Bot, dp: Dispatcher) -> None:
    """Корректное завершение работы бота."""
    log.info("Shutting down bot...")

    # Останавливаем polling
    dp.shutdown()

    # Закрываем сессию бота
    await bot.session.close()

    log.info("Bot shutdown complete")


async def main() -> None:
    global _bot, _dp, _shutdown_event

    _setup_logging()

    _bot = Bot(
        token=settings.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    _dp = Dispatcher()
    _shutdown_event = asyncio.Event()

    # Регистрируем обработчики сигналов
    if sys.platform != "win32":
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda s=sig: _handle_signal(s, None))
    else:
        # Windows не поддерживает add_signal_handler
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

    # Мидлвары
    _dp.update.middleware(LoggingMiddleware())
    _dp.update.middleware(RateLimitMiddleware(min_interval_seconds=10))

    # Роутеры
    _dp.include_router(common_router)
    _dp.include_router(scan_router)
    _dp.include_router(phone_router)
    _dp.include_router(bin_router)
    _dp.include_router(url_router)
    _dp.include_router(email_router)
    _dp.include_router(ip_router)
    _dp.include_router(username_router)
    _dp.include_router(wallet_router)
    _dp.include_router(leak_router)
    _dp.include_router(exif_router)
    # Auto-detect последним — catch-all для сообщений без команд
    _dp.include_router(auto_detect_router)

    await _bot.delete_webhook(drop_pending_updates=True)

    log.info("Bot starting polling...")

    try:
        await _dp.start_polling(_bot)
    except asyncio.CancelledError:
        log.info("Polling cancelled")
    finally:
        await _shutdown(_bot, _dp)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Bot stopped by keyboard interrupt")
