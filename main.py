# main.py
import asyncio
import logging
import os
import signal
import sys

from dotenv import load_dotenv
load_dotenv()

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.fsm.storage.memory import MemoryStorage

from config import settings
from handlers.menu import router as menu_router
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
from handlers.qr_scan import router as qr_router
from handlers.auto_detect import router as auto_detect_router
from middlewares.logging import LoggingMiddleware
from middlewares.rate_limit import RateLimitMiddleware

log = logging.getLogger(__name__)


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


async def main() -> None:
    _setup_logging()

    bot = Bot(
        token=settings.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=MemoryStorage())

    # Graceful shutdown — отменяем задачу polling по SIGINT/SIGTERM.
    # aiogram сам корректно завершит polling через CancelledError.
    loop = asyncio.get_running_loop()
    polling_task: asyncio.Task | None = None

    def _request_stop(sig_name: str) -> None:
        log.info("Received %s, stopping polling...", sig_name)
        if polling_task and not polling_task.done():
            polling_task.cancel()

    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _request_stop, sig.name)
    else:
        # Windows не поддерживает add_signal_handler для asyncio.
        # KeyboardInterrupt всё равно дойдёт до asyncio.run() и отменит таск.
        def _win_handler(signum, _frame):
            _request_stop(signal.Signals(signum).name)

        signal.signal(signal.SIGINT, _win_handler)
        signal.signal(signal.SIGTERM, _win_handler)

    # Мидлвары
    dp.update.middleware(LoggingMiddleware())
    # Rate limiter: 5 запросов подряд разрешены, потом минимум 3 сек между запросами
    dp.update.middleware(RateLimitMiddleware(
        burst_limit=5,
        window_seconds=30,
        min_interval_seconds=3,
    ))

    # Роутеры
    dp.include_router(menu_router)
    dp.include_router(scan_router)
    dp.include_router(phone_router)
    dp.include_router(bin_router)
    dp.include_router(url_router)
    dp.include_router(email_router)
    dp.include_router(ip_router)
    dp.include_router(username_router)
    dp.include_router(wallet_router)
    dp.include_router(leak_router)
    dp.include_router(qr_router)        # QR FIRST — проверяет caption "/qr"
    dp.include_router(exif_router)      # EXIF SECOND — ловит все остальные фото
    # Auto-detect последним — catch-all для сообщений без команд
    dp.include_router(auto_detect_router)

    await bot.delete_webhook(drop_pending_updates=True)

    log.info("Bot starting polling...")

    try:
        polling_task = asyncio.create_task(dp.start_polling(bot))
        await polling_task
    except asyncio.CancelledError:
        log.info("Polling cancelled")
    finally:
        log.info("Shutting down bot...")
        await bot.session.close()
        log.info("Bot shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Bot stopped by keyboard interrupt")
