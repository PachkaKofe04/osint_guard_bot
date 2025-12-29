# utils/cache.py
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Generic, Hashable, Optional, TypeVar


T = TypeVar("T")


@dataclass
class CacheEntry(Generic[T]):
    value: T
    expires_at: float


class TTLCache(Generic[T]):
    """
    Простейший TTL-кэш в памяти.
    - ключи: любые hashable (обычно строки)
    - значения: любые
    - ttl_seconds: время жизни записи
    - max_size: грубый лимит по количеству элементов
    """

    def __init__(self, ttl_seconds: int = 600, max_size: int = 1024) -> None:
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._store: Dict[Hashable, CacheEntry[T]] = {}

    def _now(self) -> float:
        return time.time()

    def _cleanup_expired(self) -> None:
        now = self._now()
        expired_keys = [k for k, v in self._store.items() if v.expires_at <= now]
        for k in expired_keys:
            self._store.pop(k, None)

    def _evict_one(self) -> None:
        """
        Грубая эвакуация: сначала чистим протухшие,
        если всё ещё много — выкидываем первый попавшийся ключ.
        """
        self._cleanup_expired()
        if len(self._store) <= self._max_size:
            return

        # удалить произвольный элемент
        for k in list(self._store.keys())[:1]:
            self._store.pop(k, None)

    def get(self, key: Hashable) -> Optional[T]:
        entry = self._store.get(key)
        if not entry:
            return None

        if entry.expires_at <= self._now():
            # протухло
            self._store.pop(key, None)
            return None

        return entry.value

    def set(self, key: Hashable, value: T) -> None:
        if len(self._store) >= self._max_size:
            self._evict_one()

        expires_at = self._now() + self._ttl
        self._store[key] = CacheEntry(value=value, expires_at=expires_at)

    def clear(self) -> None:
        self._store.clear()
