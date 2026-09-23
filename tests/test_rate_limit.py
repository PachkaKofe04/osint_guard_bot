# tests/test_rate_limit.py
"""Тесты для RateLimitMiddleware (burst-based rate limiter)."""
import time

from middlewares.rate_limit import (
    RateLimitMiddleware,
    MAX_RATE_LIMIT_ENTRIES,
    ENTRY_TTL_SECONDS,
)


class TestRateLimitMiddleware:
    """Тесты для RateLimitMiddleware."""

    def test_init_default_params(self):
        """Инициализация с параметрами по умолчанию."""
        middleware = RateLimitMiddleware()
        # См. дефолты в __init__: burst_limit=5, window_seconds=30, min_interval=3
        assert middleware.burst_limit == 5
        assert middleware.window_seconds == 30
        assert middleware.min_interval == 3

    def test_init_custom_params(self):
        """Инициализация с кастомными параметрами."""
        middleware = RateLimitMiddleware(
            burst_limit=10,
            window_seconds=60,
            min_interval_seconds=30,
        )
        assert middleware.burst_limit == 10
        assert middleware.window_seconds == 60
        assert middleware.min_interval == 30

    def test_cleanup_removes_stale_users(self):
        """Юзер, у которого все timestamp'ы старше TTL, удаляется целиком."""
        middleware = RateLimitMiddleware()
        now = time.time()

        # user 123 — все запросы старше TTL → будет удалён
        middleware._request_history[123] = [now - ENTRY_TTL_SECONDS - 100]
        # user 456 — свежий запрос → останется
        middleware._request_history[456] = [now]
        # Форсируем cleanup (иначе он пропускается чаще раза в минуту)
        middleware._last_cleanup = now - 120

        middleware._cleanup_stale_entries()

        assert 123 not in middleware._request_history
        assert 456 in middleware._request_history

    def test_cleanup_keeps_recent_timestamps(self):
        """У юзера со смесью старых и свежих timestamp'ов остаются только свежие."""
        middleware = RateLimitMiddleware()
        now = time.time()

        middleware._request_history[1] = [
            now - ENTRY_TTL_SECONDS - 10,  # устаревший
            now - 5,                        # свежий
        ]
        middleware._last_cleanup = now - 120

        middleware._cleanup_stale_entries()

        assert 1 in middleware._request_history
        assert len(middleware._request_history[1]) == 1
        assert middleware._request_history[1][0] > now - 10

    def test_max_entries_protection(self):
        """При переполнении аварийный cleanup урезает до MAX_RATE_LIMIT_ENTRIES // 2."""
        middleware = RateLimitMiddleware()
        now = time.time()

        # Все юзеры с СВЕЖИМ timestamp'ом, чтобы их не снесло по stale-пути.
        # Иначе emergency-ветка не сработает.
        for i in range(MAX_RATE_LIMIT_ENTRIES + 100):
            middleware._request_history[i] = [now - (i % 10)]
        middleware._last_cleanup = now - 120

        middleware._cleanup_stale_entries()

        assert len(middleware._request_history) <= MAX_RATE_LIMIT_ENTRIES

    def test_cleanup_not_too_frequent(self):
        """Повторный cleanup в пределах 60 секунд — no-op."""
        middleware = RateLimitMiddleware()
        now = time.time()

        # Старая запись, которую «в честной» очистке снесло бы
        middleware._request_history[123] = [now - ENTRY_TTL_SECONDS - 100]
        # Но последний cleanup был только что
        middleware._last_cleanup = now

        middleware._cleanup_stale_entries()

        # Cleanup не должен был сработать
        assert 123 in middleware._request_history


class TestIsScanRequest:
    """
    Квота тратится только на сообщения, реально уходящие во внешние API.
    Раньше в неё попадало всё подряд, включая нажатия inline-кнопок.
    """

    @staticmethod
    def _msg(text=None, photo=None, document=None):
        class _M:
            pass
        m = _M()
        m.text = text
        m.photo = photo
        m.document = document
        return m

    def test_command_with_argument_is_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg("/ip 8.8.8.8")) is True

    def test_command_without_argument_is_not_scan(self):
        """«/ip» печатает подсказку и никуда не ходит."""
        assert RateLimitMiddleware._is_scan_request(self._msg("/ip")) is False

    def test_command_with_blank_argument_is_not_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg("/ip    ")) is False

    def test_command_with_bot_suffix(self):
        """В группах команды приходят как /ip@my_bot."""
        assert RateLimitMiddleware._is_scan_request(self._msg("/ip@my_bot 8.8.8.8")) is True

    def test_navigation_command_is_not_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg("/start")) is False
        assert RateLimitMiddleware._is_scan_request(self._msg("/menu")) is False

    def test_unknown_command_is_not_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg("/whatever arg")) is False

    def test_photo_is_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg(photo=["x"])) is True

    def test_document_is_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg(document=object())) is True

    def test_scannable_plain_text_is_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg("google.com")) is True
        assert RateLimitMiddleware._is_scan_request(self._msg("+79991234567")) is True

    def test_chat_text_is_not_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg("привет")) is False
        assert RateLimitMiddleware._is_scan_request(self._msg("help")) is False

    def test_empty_message_is_not_scan(self):
        assert RateLimitMiddleware._is_scan_request(self._msg()) is False
