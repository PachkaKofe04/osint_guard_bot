# tests/test_rate_limit.py
"""Тесты для RateLimitMiddleware."""
import pytest
import time
from middlewares.rate_limit import RateLimitMiddleware, MAX_RATE_LIMIT_ENTRIES


class TestRateLimitMiddleware:
    """Тесты для RateLimitMiddleware."""

    def test_init_default_interval(self):
        """Инициализация с интервалом по умолчанию."""
        middleware = RateLimitMiddleware()
        assert middleware.min_interval == 10

    def test_init_custom_interval(self):
        """Инициализация с кастомным интервалом."""
        middleware = RateLimitMiddleware(min_interval_seconds=30)
        assert middleware.min_interval == 30

    def test_cleanup_removes_stale_entries(self):
        """Очистка удаляет устаревшие записи."""
        middleware = RateLimitMiddleware()

        # Добавляем запись час назад
        old_time = time.time() - 7200  # 2 часа назад
        middleware._last_call[123] = old_time
        middleware._last_call[456] = time.time()  # сейчас
        middleware._last_cleanup = time.time() - 120  # 2 минуты назад

        middleware._cleanup_stale_entries()

        # Старая запись должна быть удалена
        assert 123 not in middleware._last_call
        assert 456 in middleware._last_call

    def test_max_entries_protection(self):
        """Защита от переполнения."""
        middleware = RateLimitMiddleware()
        middleware._last_cleanup = time.time() - 120

        # Добавляем много записей
        for i in range(MAX_RATE_LIMIT_ENTRIES + 100):
            middleware._last_call[i] = time.time() - i

        middleware._cleanup_stale_entries()

        # После очистки должно быть не больше MAX_RATE_LIMIT_ENTRIES
        assert len(middleware._last_call) <= MAX_RATE_LIMIT_ENTRIES

    def test_cleanup_not_too_frequent(self):
        """Очистка не происходит слишком часто."""
        middleware = RateLimitMiddleware()

        # Добавляем старую запись
        middleware._last_call[123] = time.time() - 7200
        middleware._last_cleanup = time.time()  # только что была очистка

        middleware._cleanup_stale_entries()

        # Запись не должна быть удалена, т.к. очистка была недавно
        assert 123 in middleware._last_call
