# main.py
import asyncio
import logging
import os

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
from middlewares.logging import LoggingMiddleware
from middlewares.rate_limit import RateLimitMiddleware


async def main() -> None:
    # Создаём папку для логов
    os.makedirs("logs", exist_ok=True)

    # Логирование и в консоль, и в файл
    log_format = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("logs/app.log", encoding="utf-8"),
        ],
    )

    bot = Bot(
        token=settings.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    dp = Dispatcher()

    # Мидлвары
    dp.update.middleware(LoggingMiddleware())
    dp.update.middleware(RateLimitMiddleware(min_interval_seconds=10))

    # Роутеры
    dp.include_router(common_router)
    dp.include_router(scan_router)
    dp.include_router(phone_router)
    dp.include_router(bin_router)

    await bot.delete_webhook(drop_pending_updates=True)

    logging.getLogger(__name__).info("Bot starting polling...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
