# tests/test_handlers_wiring.py
"""
Тесты маршрутизации: синтетические Update'ы через настоящий Dispatcher.

Закрывают два класса поломок, не видных при чтении кода:
  - rate limiter съедал нажатия inline-кнопок;
  - бот молчал на неизвестные команды и обычный текст.

Ни одного обращения в сеть: Bot подменён, сканеры не вызываются
(тестируются только ветки, которые до них не доходят).
"""
import dataclasses
import datetime
import tempfile

import pytest
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import CallbackQuery, Chat, Message, Update, User

from handlers.monitor import set_storage
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
    Тот же диспетчер, что собирает main.py.

    Собираем именно продовой функцией, а не отдельной копией: иначе тесты
    проверяли бы сборку, которая никогда не запускается, и рассинхрон
    порядка роутеров остался бы незамеченным.

    Модульная область видимости вынужденная: роутеры в aiogram - модульные
    синглтоны и не могут быть присоединены к двум Dispatcher'ам.
    Состояние между тестами сбрасывает фикстура dp.
    """
    from main import build_dispatcher
    from monitoring.storage import MonitorStorage

    set_storage(MonitorStorage(filepath=str(tempfile.mkstemp(suffix=".json")[1])))
    return build_dispatcher()


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
    """Команда без аргумента никуда не ходит - квоту тратить незачем."""

    async def test_many_menu_commands_all_answered(self, dp, bot):
        for i in range(15):
            await feed(dp, bot, i + 1, message=make_message("/menu", mid=i + 1))

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
    async def test_start_sends_persistent_and_inline_menu(self, dp, bot):
        """/start даёт постоянную кнопку «Меню» и инлайн-меню разделов."""
        await feed(dp, bot, 1, message=make_message("/start"))

        markups = [c.reply_markup for c in bot.calls]
        assert any(
            getattr(m, "keyboard", None) for m in markups
        ), "нет постоянной ReplyKeyboard"
        assert any(
            getattr(m, "inline_keyboard", None) for m in markups
        ), "нет инлайн-меню разделов"

    async def test_main_menu_has_buttons(self, dp, bot):
        await feed(dp, bot, 1, message=make_message("/menu"))

        markup = bot.calls[-1].reply_markup
        assert markup is not None
        assert len(markup.inline_keyboard) >= 4

    async def test_persistent_button_opens_menu(self, dp, bot):
        """Кнопка «☰ Меню» под полем ввода приходит как обычный текст."""
        from keyboards.menu_kb import MENU_BUTTON_TEXT

        await feed(dp, bot, 1, message=make_message(MENU_BUTTON_TEXT))

        assert bot.calls, "бот промолчал на постоянную кнопку"
        assert bot.calls[-1].reply_markup.inline_keyboard

    async def test_unknown_category_gets_alert(self, dp, bot):
        await feed(dp, bot, 1, callback_query=make_callback("menu:cat:no_such"))

        assert bot.method_names() == ["AnswerCallbackQuery"]
        assert bot.calls[0].show_alert is True


class TestButtonMenuIsComplete:
    """
    Каждая кнопка меню должна что-то делать.

    Раньше разделы «Домен», «QR» и «Мониторинг» отвечали «Раздел не найден»,
    потому что кнопки и обработчики жили отдельно и разошлись. Теперь меню
    строится из scan_registry, а эти тесты проверяют, что связь не порвалась.
    """

    @staticmethod
    def _all_callback_data():
        """Собирает callback_data со всех экранов меню."""
        from keyboards.menu_kb import (
            get_category_menu,
            get_main_menu,
            get_monitor_menu,
            get_more_menu,
        )
        from scan_registry import CATEGORIES

        markups = [get_main_menu(), get_more_menu(), get_monitor_menu(True)]
        markups += [get_category_menu(c.key) for c in CATEGORIES]

        data = []
        for markup in markups:
            for row in markup.inline_keyboard:
                for button in row:
                    if button.callback_data:
                        data.append(button.callback_data)
        return sorted(set(data))

    def test_callback_data_fits_telegram_limit(self):
        """Telegram отвергает callback_data длиннее 64 байт."""
        for data in self._all_callback_data():
            assert len(data.encode("utf-8")) <= 64, data

    async def test_every_menu_button_answers(self, dp, bot):
        """Ни одна кнопка не должна оставлять пользователя без реакции."""
        silent = []
        for i, data in enumerate(self._all_callback_data()):
            bot.calls.clear()
            await feed(dp, bot, i + 1, callback_query=make_callback(data, mid=i + 500))
            if not bot.calls:
                silent.append(data)

        assert not silent, f"кнопки без реакции: {silent}"

    async def test_no_button_reports_section_not_found(self, dp, bot):
        """Формулировка «не найден» означает рассинхрон меню и обработчиков."""
        broken = []
        for i, data in enumerate(self._all_callback_data()):
            bot.calls.clear()
            await feed(dp, bot, i + 1, callback_query=make_callback(data, mid=i + 600))
            rendered = bot.texts() + " ".join(
                getattr(c, "text", "") or "" for c in bot.calls
            )
            if "не найден" in rendered or "недоступно" in rendered:
                broken.append(data)

        assert not broken, f"кнопки сообщают о ненайденном разделе: {broken}"

    async def test_every_direction_is_reachable(self, dp, bot):
        """Каждое направление из реестра должно открываться кнопкой."""
        from scan_registry import DIRECTIONS

        reachable = {
            d.split(":", 1)[1]
            for d in self._all_callback_data()
            if d.startswith("scan:")
        }
        assert reachable == set(DIRECTIONS), (
            f"не попали в меню: {set(DIRECTIONS) - reachable}"
        )


class TestScanFlow:
    """Сценарий кнопка -> ввод -> результат."""

    async def test_direction_button_asks_for_input(self, dp, bot):
        await feed(dp, bot, 1, callback_query=make_callback("scan:ip"))

        assert "AnswerCallbackQuery" in bot.method_names()
        assert "IP" in bot.texts()
        # Должна быть кнопка отмены, иначе из режима ввода не выйти
        markup = bot.calls[-1].reply_markup
        assert any(
            b.callback_data == "cancel"
            for row in markup.inline_keyboard for b in row
        )

    def test_limited_direction_warns_upfront(self):
        """
        Про нерабочие источники бот предупреждает до проверки, а не после.

        Проверяется механизм, а не конкретное направление: сейчас ограниченных
        нет, но как только появится - предупреждение обязано попасть на экран
        ввода, до того как пользователь потратит время на запрос.
        """
        from handlers.scan_flow import build_prompt
        from scan_registry import STATUS_LIMITED, DIRECTIONS

        sample = next(iter(DIRECTIONS.values()))
        limited = dataclasses.replace(
            sample,
            status=STATUS_LIMITED,
            status_note="Источник данных не отвечает",
        )

        prompt = build_prompt(limited)
        assert "частично" in prompt.lower()
        assert "Источник данных не отвечает" in prompt

    def test_working_direction_has_no_warning(self):
        from handlers.scan_flow import build_prompt
        from scan_registry import DIRECTIONS

        prompt = build_prompt(DIRECTIONS["ip"])
        assert "частично" not in prompt.lower()

    async def test_cancel_returns_to_menu(self, dp, bot):
        await feed(dp, bot, 1, callback_query=make_callback("scan:ip"))
        bot.calls.clear()
        await feed(dp, bot, 2, callback_query=make_callback("cancel"))

        assert bot.calls[-1].reply_markup.inline_keyboard
        assert "Отмен" in bot.texts()

    async def test_image_direction_rejects_text(self, dp, bot):
        """EXIF ждёт файл: на текст надо объяснить, а не молча падать."""
        await feed(dp, bot, 1, callback_query=make_callback("scan:exif"))
        bot.calls.clear()
        await feed(dp, bot, 2, message=make_message("просто текст"))

        assert "изображение" in bot.texts().lower()


class TestSourcesScreen:
    """Экран статуса источников: бот честно говорит, что работает не полностью."""

    async def test_sources_screen_lists_limited(self, dp, bot):
        from scan_registry import limited_directions

        await feed(dp, bot, 1, callback_query=make_callback("menu:sources"))

        rendered = bot.texts()
        for direction in limited_directions():
            assert direction.title in rendered, direction.title


class TestCommandAliases:
    """
    Команды ведут в тот же сценарий, что и кнопки.

    Раньше на каждое направление был отдельный файл-хендлер со своими
    текстами и своим поведением при пустом аргументе - семь копий,
    расходившихся между собой.
    """

    @staticmethod
    def _commands():
        from scan_registry import DIRECTIONS

        return [
            (d, d.commands[0])
            for d in DIRECTIONS.values()
            if d.commands
        ]

    async def test_every_registry_command_answers(self, dp, bot):
        """Каждая команда из реестра должна быть обработана."""
        silent = []
        for i, (_direction, command) in enumerate(self._commands()):
            bot.calls.clear()
            await feed(dp, bot, i + 1, message=make_message(command, mid=i + 800))
            if not bot.calls:
                silent.append(command)

        assert not silent, f"команды без ответа: {silent}"

    async def test_command_without_argument_opens_input_screen(self, dp, bot):
        """«/ip» без аргумента открывает тот же экран, что кнопка IP-адрес."""
        await feed(dp, bot, 1, message=make_message("/ip"))

        markup = bot.calls[-1].reply_markup
        assert any(
            b.callback_data == "cancel"
            for row in markup.inline_keyboard for b in row
        ), "нет кнопки отмены - из режима ввода не выйти"

    async def test_command_and_button_show_same_prompt(self, dp, bot):
        """Текст экрана ввода не должен зависеть от способа входа."""
        from handlers.scan_flow import build_prompt
        from scan_registry import get_direction

        await feed(dp, bot, 1, message=make_message("/ip"))
        via_command = bot.texts()

        assert build_prompt(get_direction("ip")) in via_command

    async def test_unknown_command_still_reports(self, dp, bot):
        await feed(dp, bot, 1, message=make_message("/definitely_not_a_command"))

        assert "неизвестна" in bot.texts()


class TestStateDoesNotTrapUser:
    """
    Из режима ожидания ввода всегда есть выход.

    Хендлер «неподходящий тип сообщения» ловил в том числе команды,
    и пользователь застревал: «/ip 8.8.8.8» получал ответ
    «с таким типом сообщений я не работаю».
    """

    async def test_command_works_while_waiting_for_input(self, dp, bot):
        await feed(dp, bot, 1, callback_query=make_callback("scan:domain"))
        bot.calls.clear()

        await feed(dp, bot, 2, message=make_message("/ip"))

        assert "IP" in bot.texts()
        assert "не работаю" not in bot.texts()

    async def test_start_works_while_waiting_for_input(self, dp, bot):
        await feed(dp, bot, 1, callback_query=make_callback("scan:domain"))
        bot.calls.clear()

        await feed(dp, bot, 2, message=make_message("/start"))

        assert "не работаю" not in bot.texts()
        assert bot.calls

    async def test_menu_button_works_while_waiting_for_input(self, dp, bot):
        from keyboards.menu_kb import MENU_BUTTON_TEXT

        await feed(dp, bot, 1, callback_query=make_callback("scan:domain"))
        bot.calls.clear()

        await feed(dp, bot, 2, message=make_message(MENU_BUTTON_TEXT))

        assert "не работаю" not in bot.texts()
        assert bot.calls[-1].reply_markup.inline_keyboard


class TestInputValidation:
    """
    Мусор не должен доходить до сканера.

    В кнопочном сценарии проверки не было вовсе: одиночный «+» доходил до
    телефонного сканера и получал оценку «Средний риск 6/10» со всеми
    признаками настоящего анализа - «неверная длина номера: 0 цифр».
    """

    @pytest.mark.parametrize("value", ["+", "абвгд", "???", "a"])
    async def test_garbage_rejected_for_phone(self, dp, bot, value):
        await feed(dp, bot, 1, callback_query=make_callback("scan:phone"))
        bot.calls.clear()
        await feed(dp, bot, 2, message=make_message(value))

        assert "не похоже на номер телефона" in bot.texts()

    async def test_user_stays_in_input_mode_after_mistake(self, dp, bot):
        """Ошибка ввода не выбрасывает из режима: можно просто прислать снова."""
        await feed(dp, bot, 1, callback_query=make_callback("scan:phone"))
        bot.calls.clear()
        await feed(dp, bot, 2, message=make_message("+"))

        markup = bot.calls[-1].reply_markup
        assert any(
            b.callback_data == "cancel"
            for row in markup.inline_keyboard for b in row
        ), "после ошибки должна остаться кнопка отмены"

    async def test_wrong_section_hints_the_right_one(self, dp, bot):
        """Домен в разделе email: подсказываем, куда идти."""
        await feed(dp, bot, 1, callback_query=make_callback("scan:email"))
        bot.calls.clear()
        await feed(dp, bot, 2, message=make_message("fonbet.ru"))

        text = bot.texts()
        assert "не похоже на email" in text
        assert "адрес сайта" in text

    async def test_valid_input_is_not_blocked(self, dp, bot):
        from handlers.scan_flow import validation_error
        from scan_registry import DIRECTIONS

        valid = {
            "phone": "+79991234567",
            "email": "user@example.com",
            "domain": "example.com",
            "ip": "8.8.8.8",
            "bin": "427229",
            "username": "johndoe",
            "wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        }
        for key, value in valid.items():
            assert validation_error(DIRECTIONS[key], value) is None, f"{key}: {value}"

    async def test_command_with_garbage_rejected(self, dp, bot):
        """«/phone +» должен вести себя так же, как кнопочный сценарий."""
        await feed(dp, bot, 1, message=make_message("/phone +"))

        assert "не похоже на номер телефона" in bot.texts()


class TestResultCardSurvivesNavigation:
    """
    Карточка результата не должна стираться кнопкой навигации.

    Кнопка «В меню» делала edit_text и заменяла текст отчёта главным меню:
    пользователь получал разбор по утечкам, нажимал «В меню» и терял его
    безвозвратно. Для экранов меню перерисовка на месте правильна, для
    сообщений с данными - разрушительна.
    """

    @staticmethod
    def _result_card_buttons():
        from keyboards.menu_kb import get_back_menu, get_result_menu
        from scan_registry import DIRECTIONS

        markups = [get_back_menu(), get_result_menu(DIRECTIONS["ip"], value="8.8.8.8")]
        return [
            b.callback_data
            for m in markups for row in m.inline_keyboard for b in row
            if b.callback_data
        ]

    def test_cards_never_use_editing_menu_button(self):
        """На карточке не должно быть кнопки, перерисовывающей сообщение."""
        assert "menu:main" not in self._result_card_buttons()

    def test_cards_offer_non_destructive_menu(self):
        assert "menu:fresh" in self._result_card_buttons()

    def test_navigation_screens_still_edit_in_place(self):
        """В меню перерисовка на месте остаётся: там нечего терять."""
        from keyboards.menu_kb import get_category_menu, get_more_menu

        for markup in (get_category_menu("web"), get_more_menu()):
            data = [
                b.callback_data
                for row in markup.inline_keyboard for b in row if b.callback_data
            ]
            assert "menu:main" in data

    async def test_fresh_menu_sends_new_message(self, dp, bot):
        await feed(dp, bot, 1, callback_query=make_callback("menu:fresh"))

        names = bot.method_names()
        assert "SendMessage" in names, "меню должно прийти новым сообщением"
        assert "EditMessageText" not in names, "текст отчёта затирать нельзя"

    async def test_fresh_menu_removes_card_buttons(self, dp, bot):
        """Кнопки с карточки снимаются: повторное нажатие уже бессмысленно."""
        await feed(dp, bot, 1, callback_query=make_callback("menu:fresh"))

        assert "EditMessageReplyMarkup" in bot.method_names()


class TestImageAutoDispatch:
    """
    Изображение без подписи: сначала QR, потом метаданные.

    Раньше всё безусловно уходило в EXIF, и человек, приславший очевидную
    картинку с QR-кодом, получал в ответ «GPS координаты отсутствуют».
    """

    qrcode = pytest.importorskip("qrcode")

    @staticmethod
    def _qr_png(text):
        import io

        import qrcode as qr_lib

        code = qr_lib.QRCode(box_size=8, border=4)
        code.add_data(text)
        code.make(fit=True)
        buffer = io.BytesIO()
        code.make_image(fill_color="black", back_color="white").convert("RGB").save(
            buffer, "PNG"
        )
        return buffer.getvalue()

    @staticmethod
    def _plain_jpeg():
        import io

        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (800, 600), (120, 120, 120)).save(buffer, "JPEG")
        return buffer.getvalue()

    async def test_image_with_qr_is_decoded(self):
        from qr_scanner.scanner import scan_qr

        result = await scan_qr(self._qr_png("https://t.me/channel"), "IMG_0761.PNG")
        assert result.found_qr
        assert result.info.raw_data == "https://t.me/channel"

    async def test_image_without_qr_falls_through(self):
        """Обычное фото не должно выдавать ложный QR."""
        from qr_scanner.scanner import scan_qr

        result = await scan_qr(self._plain_jpeg(), "IMG_1129.jpg")
        assert result.found_qr is False

    async def test_metadata_hint_mentions_camera(self):
        """Метаданные не должны потеряться за ответом про QR."""
        import io

        from PIL import Image

        from handlers.media import _exif_hint

        source = Image.open(io.BytesIO(self._qr_png("test")))
        canvas = Image.new("RGB", (1600, 1600), (230, 230, 225))
        canvas.paste(source, (400, 400))

        exif = Image.Exif()
        exif[0x0110] = "iPhone 13 mini"
        buffer = io.BytesIO()
        canvas.save(buffer, "JPEG", exif=exif.tobytes())

        hint = await _exif_hint(buffer.getvalue(), "IMG_9000.jpg")
        assert "iPhone 13 mini" in hint

    async def test_no_hint_when_no_metadata(self):
        from handlers.media import _exif_hint

        assert await _exif_hint(self._plain_jpeg(), "plain.jpg") == ""
