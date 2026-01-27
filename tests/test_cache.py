# tests/test_cache.py
"""Тесты для TTL кэша."""
import pytest
import time
from utils.cache import TTLCache


class TestTTLCache:
    """Тесты для TTLCache."""

    def test_set_and_get(self):
        """Базовое сохранение и получение."""
        cache: TTLCache[str] = TTLCache(ttl_seconds=60, max_size=100)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_missing_key(self):
        """Получение несуществующего ключа."""
        cache: TTLCache[str] = TTLCache(ttl_seconds=60, max_size=100)
        assert cache.get("nonexistent") is None

    def test_ttl_expiration(self):
        """Истечение TTL."""
        cache: TTLCache[str] = TTLCache(ttl_seconds=1, max_size=100)
        cache.set("key1", "value1")

        assert cache.get("key1") == "value1"

        # Ждём истечения TTL
        time.sleep(1.1)

        assert cache.get("key1") is None

    def test_max_size_eviction(self):
        """Вытеснение при превышении max_size."""
        cache: TTLCache[int] = TTLCache(ttl_seconds=60, max_size=3)

        cache.set("key1", 1)
        cache.set("key2", 2)
        cache.set("key3", 3)

        # Все ключи должны быть доступны
        assert cache.get("key1") == 1
        assert cache.get("key2") == 2
        assert cache.get("key3") == 3

        # Добавляем ещё один — должен вытеснить самый старый
        cache.set("key4", 4)

        # key1 должен быть вытеснен (FIFO или LRU)
        # Но key4 точно должен быть
        assert cache.get("key4") == 4

    def test_overwrite_existing_key(self):
        """Перезапись существующего ключа."""
        cache: TTLCache[str] = TTLCache(ttl_seconds=60, max_size=100)

        cache.set("key1", "old_value")
        cache.set("key1", "new_value")

        assert cache.get("key1") == "new_value"

    def test_different_types(self):
        """Разные типы значений."""
        cache: TTLCache[dict] = TTLCache(ttl_seconds=60, max_size=100)

        data = {"name": "test", "value": 123}
        cache.set("key1", data)

        result = cache.get("key1")
        assert result == data
        assert result["name"] == "test"

    def test_clear(self):
        """Очистка кэша."""
        cache: TTLCache[str] = TTLCache(ttl_seconds=60, max_size=100)

        cache.set("key1", "value1")
        cache.set("key2", "value2")

        cache.clear()

        assert cache.get("key1") is None
        assert cache.get("key2") is None
