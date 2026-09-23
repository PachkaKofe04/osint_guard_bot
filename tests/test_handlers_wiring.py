# tests/test_handlers_wiring.py
"""
Тесты маршрутизации: синтетические Update'ы через настоящий Dispatcher.

Закрывают два класса поломок, не видных при чтении кода:
  - rate limiter съедал нажатия inline-кнопок;
  - бот молчал на неизвестные команды и обычный текст.

Ни одного обращения в сеть: Bot подменён, сканеры не вызываются
(тестируются только ветки, которые до них не доходят).
"""
import datetime

import pytest
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import CallbackQuery, Chat, Message, Update, User

from handlers.auto_detect import router as auto_detect_router
from handlers.menu import router as menu_router
from middlewares.rate_limit import RateLimitMiddleware

FAKE_TOKEN = "123456:AAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAa"

USER = User(id=777, is_bot=False, first_name="Tester", username="tester")
CHAT = Chat(id=777, type="private")
BOT_USER = User(id=42, is_bot=True, first_name="bot")


class RecordingBot(Bot):
    """Перехватывает исходящие вызовы API вместо обращения к Telegram."""

    def __init__(self) -> None:
        super().__init__(
            token=FAKE_TOKEN,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        )
        self.calls: list = []

    async def __call__(self, method, request_timeout=None):
        self.calls.append(method)
        name = type(method).__name__
        if name in ("SendMessage", "EditMessageText"):
            return Message(
                message_id=999,
                date=datetime.datetime.now(),
                chat=CHAT,
                from_user=BOT_USER,
                text=getattr(method, "text", "") or "",
            )
        return True

    def method_names(self) -> list:
        return [type(m).__name__ for m in self.calls]

    def texts(self) -> str:
        return "\n".join(getattr(m, "text", "") or "" for m in self.calls)


def make_message(text: str, mid: int = 1) -> Message:
    return Message(
        message_id=mid,
        date=datetime.datetime.now(),
        chat=CHAT,
        from_user=USER,
        text=text,
    )


def make_callback(data: str, mid: int = 2) -> CallbackQuery:
    return CallbackQuery(
        id=f"cb{mid}",
        from_user=USER,
        chat_instance="ci",
        data=data,
        message=Message(
            message_id=mid,
            date=datetime.datetime.now(),
            chat=CHAT,
            from_user=BOT_USER,
            text="предыдущее сообщение бота",
        ),
    )


@pytest.fixture
def bot() -> RecordingBot:
    return RecordingBot()


@pytest.fixture(scope="module")
def _dispatcher() -> Dispatcher:
    """
    Диспетчер с rate limiter — как в проде.

    Модульная область видимости вынужденная: роутеры в aiogram — модульные
    синглтоны и не могут быть присоединены к двум Dispatcher'ам.
    Состояние между тестами сбрасывает фикстура dp.
    """
    dispatcher = Dispatcher(storage=MemoryStorage())
    dispatcher.update.middleware(
        RateLimitMiddleware(burst_limit=5, window_seconds=30, min_interval_seconds=3)
    )
    dispatcher.include_router(menu_router)
    dispatcher.include_router(auto_detect_router)
    return dispatcher


def _rate_limiter(dispatcher: Dispatcher) -> RateLimitMiddleware:
    return next(
        m for m in dispatcher.update.middleware
        if isinstance(m, RateLimitMiddleware)
    )


@pytest.fixture
def dp(_dispatcher: Dispatcher) -> Dispatcher:
    """Тот же диспетчер, но с чистой историей rate limiter'а."""
    _rate_limiter(_dispatcher)._request_history.clear()
    return _dispatcher


async def feed(dp: Dispatcher, bot: RecordingBot, update_id: int, **kwargs) -> None:
    await dp.feed_update(bot, Update(update_id=update_id, **kwargs))


class TestButtonsNotRateLimited:
    """После 5 кликов меню умирало: callback'и попадали в квоту сканов."""

    async def test_twenty_button_presses_all_answered(self, dp, bot):
        for i in range(20):
            await feed(dp, bot, i + 1, callback_query=make_callback("menu:main", mid=i + 100))

        names = bot.method_names()
        assert names.count("AnswerCallbackQuery") == 20, (
            "каждое нажатие обязано получить answer, иначе в клиенте висят «часики»"
        )
        assert names.count("EditMessageText") == 20

    async def test_no_rate_limit_message_on_buttons(self, dp, bot):
        for i in range(20):
            await feed(dp, bot, i + 1, callback_query=make_callback("help:email", mid=i + 200))

        assert "Слишком много" not in bot.texts()

    async def test_rate_limiter_history_untouched_by_callbacks(self, dp, bot):
        middleware = _rate_limiter(dp)
        for i in range(10):
            await feed(dp, bot, i + 1, callback_query=make_callback("menu:main", mid=i + 300))

        assert USER.id not in middleware._request_history


class TestUsageHintsNotRateLimited:
    """Команда без аргумента никуда не ходит — квоту тратить незачем."""

    async def test_many_menu_commands_all_answered(self, dp, bot):
        for i in range(15):
            await feed(dp, bot, i + 1, message=make_message("/start", mid=i + 1))

        assert bot.method_names().count("SendMessage") == 15
        assert "Слишком много" not in bot.texts()


class TestBotAlwaysAnswers:
    """Раньше на эти вводы бот молчал."""

    @pytest.mark.parametrize("command", ["/nonexistent", "/settings", "/about", "/stats"])
    async def test_unknown_command_gets_reply(self, dp, bot, command):
        await feed(dp, bot, 1, message=make_message(command))

        assert bot.calls, f"бот промолчал на {command}"
        assert "неизвестна" in bot.texts()

    @pytest.mark.parametrize("text", ["привет", "как дела", "спасибо", "?", "ok", "help"])
    async def test_unknown_text_gets_reply(self, dp, bot, text):
        await feed(dp, bot, 1, message=make_message(text))

        assert bot.calls, f"бот промолчал на {text!r}"
        assert "Не понял" in bot.texts()

    async def test_reply_offers_menu(self, dp, bot):
        await feed(dp, bot, 1, message=make_message("привет"))

        markup = bot.calls[0].reply_markup
        assert markup is not None, "ответ должен вести в меню кнопками"
        assert markup.inline_keyboard

    async def test_ambiguous_word_asks_instead_of_scanning(self, dp, bot):
        """Незнакомое слово не должно молча уходить в скан по 20 платформам."""
        await feed(dp, bot, 1, message=make_message("torvalds"))

        assert "никнейм" in bot.texts()
        markup = bot.calls[0].reply_markup
        assert any(
            btn.callback_data and btn.callback_data.startswith("asname:")
            for row in markup.inline_keyboard for btn in row
        )


class TestMenuNavigation:
    async def test_main_menu_has_buttons(self, dp, bot):
        await feed(dp, bot, 1, message=make_message("/start"))

        markup = bot.calls[0].reply_markup
        assert markup is not None
        assert len(markup.inline_keyboard) >= 4

    async def test_unknown_section_gets_alert(self, dp, bot):
        await feed(dp, bot, 1, callback_query=make_callback("help:no_such_section"))

        assert bot.method_names() == ["AnswerCallbackQuery"]
        assert bot.calls[0].show_alert is True
