"""Прогон синтетических апдейтов через реальный Dispatcher с мок-ботом."""
import asyncio, datetime, logging, sys
from unittest.mock import patch

logging.disable(logging.CRITICAL)

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.methods import SendMessage, EditMessageText, AnswerCallbackQuery, EditMessageReplyMarkup, SendDocument
from aiogram.types import Update, Message, Chat, User, CallbackQuery, PhotoSize, Document

CALLS = []

class FakeBot(Bot):
    async def __call__(self, method, request_timeout=None):
        CALLS.append(method)
        name = type(method).__name__
        if name in ("SendMessage", "EditMessageText", "SendDocument"):
            return Message(
                message_id=999, date=datetime.datetime.now(),
                chat=Chat(id=1, type="private"),
                from_user=User(id=42, is_bot=True, first_name="bot"),
                text=getattr(method, "text", None) or "doc",
            )
        if name == "AnswerCallbackQuery":
            return True
        if name == "EditMessageReplyMarkup":
            return True
        if name == "GetFile":
            raise RuntimeError("GetFile called (сеть Telegram) — пропускаем")
        return True

USER = User(id=777, is_bot=False, first_name="Tester", username="tester")
CHAT = Chat(id=777, type="private")

def msg(text=None, mid=1, photo=False, document=None, caption=None, reply_to=None):
    kw = dict(message_id=mid, date=datetime.datetime.now(), chat=CHAT, from_user=USER)
    if text is not None:
        kw["text"] = text
    if caption is not None:
        kw["caption"] = caption
    if photo:
        kw["photo"] = [PhotoSize(file_id="f1", file_unique_id="u1", width=100, height=100)]
    if document is not None:
        kw["document"] = document
    if reply_to is not None:
        kw["reply_to_message"] = reply_to
    return Message(**kw)

def cb(data, mid=2):
    return CallbackQuery(
        id="cb1", from_user=USER, chat_instance="ci",
        data=data,
        message=Message(message_id=mid, date=datetime.datetime.now(), chat=CHAT,
                        from_user=User(id=42, is_bot=True, first_name="bot"),
                        text="предыдущее сообщение бота"),
    )

async def build_dp():
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
    from handlers.monitor import router as monitor_router, set_storage
    from monitoring.storage import MonitorStorage
    from middlewares.logging import LoggingMiddleware
    from middlewares.rate_limit import RateLimitMiddleware

    set_storage(MonitorStorage(filepath="_probe_monitors.json"))

    dp = Dispatcher(storage=MemoryStorage())
    dp.update.middleware(LoggingMiddleware())
    import os
    if not os.environ.get("NO_RL"):
        dp.update.middleware(RateLimitMiddleware(burst_limit=5, window_seconds=30, min_interval_seconds=3))
    for r in (menu_router, scan_router, phone_router, bin_router, url_router, email_router,
              ip_router, username_router, wallet_router, leak_router, qr_router, exif_router,
              monitor_router, auto_detect_router):
        dp.include_router(r)
    return dp

async def probe(dp, bot, label, update_obj):
    CALLS.clear()
    uid = probe.counter = getattr(probe, "counter", 0) + 1
    upd = Update(update_id=uid, **update_obj)
    try:
        await asyncio.wait_for(dp.feed_update(bot, upd), timeout=25)
    except asyncio.TimeoutError:
        print(f"{label:38} → ⏱ TIMEOUT (>25s)")
        return
    except Exception as e:
        print(f"{label:38} → 💥 {type(e).__name__}: {str(e)[:90]}")
        return
    if not CALLS:
        print(f"{label:38} → ∅ НЕТ ОТВЕТА (ни один хендлер не сработал)")
        return
    parts = []
    for m in CALLS:
        n = type(m).__name__
        t = (getattr(m, "text", None) or "")[:70].replace("\n", " ⏎ ")
        parts.append(f"{n}({t})")
    print(f"{label:38} → {' | '.join(parts)}")

async def main():
    bot = FakeBot(token="123456:AAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAa",
                  default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = await build_dp()

    print("=" * 110)
    print("БЛОК 1 — команды и меню (без сети, ожидаем usage-подсказки)")
    print("=" * 110)
    cases = [
        ("/start", msg("/start")),
        ("/menu", msg("/menu")),
        ("/help", msg("/help")),
        ("/scan (без аргумента)", msg("/scan")),
        ("/phone (без аргумента)", msg("/phone")),
        ("/bin (без аргумента)", msg("/bin")),
        ("/url (без аргумента)", msg("/url")),
        ("/email (без аргумента)", msg("/email")),
        ("/ip (без аргумента)", msg("/ip")),
        ("/username (без аргумента)", msg("/username")),
        ("/wallet (без аргумента)", msg("/wallet")),
        ("/leak (без аргумента)", msg("/leak")),
        ("/monitor (без аргумента)", msg("/monitor")),
        ("/monitors", msg("/monitors")),
        ("/unmonitor (без аргумента)", msg("/unmonitor")),
        ("/qr", msg("/qr")),
        ("/nonexistent", msg("/nonexistent")),
        ("/settings (нет такой)", msg("/settings")),
        ("/about (нет такой)", msg("/about")),
        ("/stats (нет такой)", msg("/stats")),
    ]
    for label, m in cases:
        await probe(dp, bot, label, {"message": m})

    print()
    print("=" * 110)
    print("БЛОК 2 — callback-кнопки")
    print("=" * 110)
    cbs = ["menu:main", "help:site", "help:email", "help:phone", "help:ip", "help:user",
           "help:bin", "help:wallet", "help:leak", "help:photo", "help:qr", "help:domain",
           "help:monitor", "help:unknown_section"]
    for c in cbs:
        await probe(dp, bot, f"callback {c}", {"callback_query": cb(c)})

    print()
    print("=" * 110)
    print("БЛОК 3 — свободный текст (auto-detect), без сети → смотрим что отвечает")
    print("=" * 110)
    texts = ["привет", "как дела", "спасибо", "?", "ok", "хочу проверить сайт",
             "проверь мне номер", "help", "меню"]
    for t in texts:
        await probe(dp, bot, f"текст {t!r}", {"message": msg(t)})

asyncio.run(main())
