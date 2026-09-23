"""
Прогон синтетических апдейтов через настоящий Dispatcher с мок-ботом.

Показывает, какой хендлер и чем ответил на каждый ввод. Ни одного реального
запроса к Telegram: Bot подменён, сетевые вызовы наружу не уходят.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tools/wiring_probe.py
    NO_RL=1 ... python tools/wiring_probe.py    # без rate limiter

Ищем в выводе: "НЕТ ОТВЕТА", "Слишком много" на кнопках, "не найден",
исключения и таймауты.
"""
import asyncio
import datetime
import logging
import os
import tempfile

logging.disable(logging.CRITICAL)

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import CallbackQuery, Chat, Document, Message, PhotoSize, Update, User

CALLS = []


class FakeBot(Bot):
    async def __call__(self, method, request_timeout=None):
        CALLS.append(method)
        name = type(method).__name__
        if name in ("SendMessage", "EditMessageText", "SendDocument"):
            return Message(
                message_id=999,
                date=datetime.datetime.now(),
                chat=Chat(id=1, type="private"),
                from_user=User(id=42, is_bot=True, first_name="bot"),
                text=getattr(method, "text", None) or "doc",
            )
        if name == "GetFile":
            raise RuntimeError("GetFile: нужен реальный Telegram, пропускаем")
        return True


USER = User(id=777, is_bot=False, first_name="Tester", username="tester")
CHAT = Chat(id=777, type="private")


def msg(text=None, mid=1, photo=False, document=None, caption=None):
    kw = dict(message_id=mid, date=datetime.datetime.now(), chat=CHAT, from_user=USER)
    if text is not None:
        kw["text"] = text
    if caption is not None:
        kw["caption"] = caption
    if photo:
        kw["photo"] = [PhotoSize(file_id="f1", file_unique_id="u1", width=100, height=100)]
    if document is not None:
        kw["document"] = document
    return Message(**kw)


def cb(data, mid=2):
    return CallbackQuery(
        id=f"cb{mid}", from_user=USER, chat_instance="ci", data=data,
        message=Message(
            message_id=mid, date=datetime.datetime.now(), chat=CHAT,
            from_user=User(id=42, is_bot=True, first_name="bot"),
            text="предыдущее сообщение бота",
        ),
    )


async def build_dp():
    from handlers.auto_detect import router as auto_detect_router
    from handlers.commands import router as commands_router
    from handlers.media import router as media_router
    from handlers.menu import router as menu_router
    from handlers.monitor import router as monitor_router, set_storage
    from handlers.monitor_menu import router as monitor_menu_router
    from handlers.result_actions import router as result_actions_router
    from handlers.scan_flow import router as scan_flow_router
    from middlewares.logging import LoggingMiddleware
    from middlewares.rate_limit import RateLimitMiddleware
    from monitoring.storage import MonitorStorage

    set_storage(MonitorStorage(filepath=tempfile.mkstemp(suffix=".json")[1]))

    dp = Dispatcher(storage=MemoryStorage())
    dp.update.middleware(LoggingMiddleware())
    if not os.environ.get("NO_RL"):
        dp.update.middleware(
            RateLimitMiddleware(burst_limit=5, window_seconds=30, min_interval_seconds=3)
        )

    for router in (
        menu_router, scan_flow_router, commands_router, result_actions_router,
        monitor_menu_router, monitor_router, media_router, auto_detect_router,
    ):
        dp.include_router(router)
    return dp


async def probe(dp, bot, label, update_obj):
    CALLS.clear()
    probe.counter = getattr(probe, "counter", 0) + 1
    upd = Update(update_id=probe.counter, **update_obj)
    try:
        await asyncio.wait_for(dp.feed_update(bot, upd), timeout=25)
    except asyncio.TimeoutError:
        print(f"{label:38} TIMEOUT (>25s)")
        return
    except Exception as exc:
        print(f"{label:38} ИСКЛЮЧЕНИЕ {type(exc).__name__}: {str(exc)[:80]}")
        return

    if not CALLS:
        print(f"{label:38} НЕТ ОТВЕТА (ни один хендлер не сработал)")
        return

    parts = []
    for m in CALLS:
        text = (getattr(m, "text", None) or "")[:62].replace("\n", " / ")
        parts.append(f"{type(m).__name__}({text})")
    print(f"{label:38} {' | '.join(parts)}")


async def main():
    from keyboards.menu_kb import (
        MENU_BUTTON_TEXT, get_category_menu, get_main_menu,
        get_monitor_menu, get_more_menu,
    )
    from scan_registry import CATEGORIES

    bot = FakeBot(
        token="123456:AAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAa",
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = await build_dp()

    print("=" * 108)
    print("БЛОК 1 - команды")
    print("=" * 108)
    for label, m in [
        ("/start", msg("/start")),
        ("/menu", msg("/menu")),
        ("/help", msg("/help")),
        ("постоянная кнопка Меню", msg(MENU_BUTTON_TEXT)),
        ("/monitors", msg("/monitors")),
        ("/nonexistent", msg("/nonexistent")),
        ("/settings", msg("/settings")),
    ]:
        await probe(dp, bot, label, {"message": m})

    print()
    print("=" * 108)
    print("БЛОК 2 - все кнопки меню")
    print("=" * 108)
    markups = [("главное", get_main_menu()), ("ещё", get_more_menu()),
               ("мониторинг", get_monitor_menu(True))]
    markups += [(c.title, get_category_menu(c.key)) for c in CATEGORIES]

    seen = set()
    for _screen, markup in markups:
        for row in markup.inline_keyboard:
            for button in row:
                data = button.callback_data
                if not data or data in seen:
                    continue
                seen.add(data)
                await probe(dp, bot, f"[{button.text}] {data}", {"callback_query": cb(data)})

    # Сбрасываем состояние: предыдущий блок оставил бота в режиме ожидания ввода
    CALLS.clear()
    await dp.feed_update(bot, Update(update_id=90000, callback_query=cb("cancel")))

    print()
    print("=" * 108)
    print("БЛОК 3 - свободный ввод")
    print("=" * 108)
    for text in ["привет", "как дела", "?", "help", "torvalds", "меню",
                 "стикер-заглушка", "1234"]:
        await probe(dp, bot, f"текст {text!r}", {"message": msg(text)})

    print()
    print("=" * 108)
    print("БЛОК 4 - сценарий проверки по кнопкам")
    print("=" * 108)
    await probe(dp, bot, "кнопка [IP-адрес]", {"callback_query": cb("scan:ip")})
    await probe(dp, bot, "кнопка [Криптокошелёк]", {"callback_query": cb("scan:wallet")})
    await probe(dp, bot, "отмена", {"callback_query": cb("cancel")})
    await probe(dp, bot, "кнопка [EXIF] + текст", {"callback_query": cb("scan:exif")})
    await probe(dp, bot, "  -> прислали текст", {"message": msg("не картинка")})
    await probe(dp, bot, "отмена", {"callback_query": cb("cancel")})


asyncio.run(main())
