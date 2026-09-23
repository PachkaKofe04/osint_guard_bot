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
from aiogram.types import BotCommand

from config import settings
from handlers.auto_detect import router as auto_detect_router
from handlers.commands import router as commands_router
from handlers.media import router as media_router
from handlers.menu import router as menu_router
from handlers.monitor import router as monitor_router, set_storage as set_monitor_storage
from handlers.monitor_menu import router as monitor_menu_router
from handlers.result_actions import router as result_actions_router
from handlers.scan_flow import router as scan_flow_router
from middlewares.logging import LoggingMiddleware
from middlewares.rate_limit import RateLimitMiddleware
from monitoring.scheduler import monitor_loop
from monitoring.storage import MonitorStorage
from scan_registry import DIRECTIONS

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


def build_bot_commands() -> list[BotCommand]:
    """
    Список для синего меню команд Telegram.

    Строится из scan_registry, поэтому не расходится с тем, что бот умеет.
    Раньше getMyCommands возвращал пустой список и пользователь не видел
    ни одной возможности бота.
    """
    commands = [
        BotCommand(command="start", description="Главное меню"),
        BotCommand(command="menu", description="Главное меню"),
    ]

    for direction in DIRECTIONS.values():
        if not direction.commands:
            continue
        primary = direction.commands[0].lstrip("/")
        commands.append(
            BotCommand(command=primary, description=direction.button)
        )

    commands.append(BotCommand(command="monitors", description="Мои объекты под наблюдением"))
    commands.append(BotCommand(command="help", description="Справка"))
    return commands


def build_dispatcher() -> Dispatcher:
    """
    Собирает диспетчер. Порядок роутеров важен.

    1. menu          - навигация, /start, постоянная кнопка «Меню»
    2. scan_flow     - состояние ожидания ввода; должно опередить media
                       и auto_detect, иначе присланное фото или текст уйдут
                       не в то направление
    3. commands      - команды-алиасы к тем же направлениям
    4. result_actions- кнопки на карточке результата
    5. monitor_menu  - мониторинг кнопками (тоже со своим состоянием)
    6. monitor       - команды мониторинга
    7. media         - фото и документы, присланные мимо меню
    8. auto_detect   - catch-all: всё остальное
    """
    dispatcher = Dispatcher(storage=MemoryStorage())

    dispatcher.update.middleware(LoggingMiddleware())
    # 5 проверок подряд, далее минимум 3 секунды между ними.
    # Нажатия кнопок в квоту не попадают - это навигация, а не скан.
    dispatcher.update.middleware(RateLimitMiddleware(
        burst_limit=5,
        window_seconds=30,
        min_interval_seconds=3,
    ))

    for router in (
        menu_router,
        scan_flow_router,
        commands_router,
        result_actions_router,
        monitor_menu_router,
        monitor_router,
        media_router,
        auto_detect_router,
    ):
        dispatcher.include_router(router)

    return dispatcher


async def main() -> None:
    _setup_logging()

    bot = Bot(
        token=settings.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    # Graceful shutdown - отменяем задачу polling по SIGINT/SIGTERM.
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

    monitor_storage = MonitorStorage()
    set_monitor_storage(monitor_storage)

    dp = build_dispatcher()

    await bot.delete_webhook(drop_pending_updates=True)

    try:
        commands = build_bot_commands()
        await bot.set_my_commands(commands)
        log.info("Registered %d commands in Telegram menu", len(commands))
    except Exception as exc:
        # Не критично для работы бота - логируем и продолжаем
        log.warning("Failed to register bot commands: %s", exc)

    log.info("Bot starting polling...")

    monitor_task: asyncio.Task | None = None
    try:
        monitor_task = asyncio.create_task(monitor_loop(bot, monitor_storage))
        polling_task = asyncio.create_task(dp.start_polling(bot))
        await polling_task
    except asyncio.CancelledError:
        log.info("Polling cancelled")
    finally:
        if monitor_task and not monitor_task.done():
            monitor_task.cancel()
        log.info("Shutting down bot...")
        await bot.session.close()
        log.info("Bot shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Bot stopped by keyboard interrupt")
