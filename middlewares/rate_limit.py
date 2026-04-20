# middlewares/rate_limit.py
import time
import logging
from typing import Any, Awaitable, Callable, Dict, List

from aiogram import BaseMiddleware
from aiogram.types import Update, Message

log = logging.getLogger(__name__)

# Максимальное количество записей в кэше rate limit
MAX_RATE_LIMIT_ENTRIES = 10000
# Время жизни записи (в секундах) — после этого запись считается устаревшей
ENTRY_TTL_SECONDS = 3600  # 1 час


class RateLimitMiddleware(BaseMiddleware):
    """
    Rate limit с burst allowance:
    - Разрешает несколько быстрых запросов подряд (burst)
    - Блокирует только при злоупотреблении (много запросов за короткое время)
    - Автоматическая очистка устаревших записей
    """

    def __init__(
        self,
        burst_limit: int = 5,           # Разрешить 5 запросов подряд
        window_seconds: int = 30,       # За последние 30 секунд
        min_interval_seconds: int = 3,  # Минимум 3 сек между запросами после burst
    ) -> None:
        super().__init__()
        self.burst_limit = burst_limit
        self.window_seconds = window_seconds
        self.min_interval = min_interval_seconds
        self._request_history: Dict[int, List[float]] = {}
        self._last_cleanup: float = time.time()

    def _cleanup_stale_entries(self) -> None:
        """Удаляет устаревшие записи из словаря."""
        now = time.time()
        # Очистка не чаще раза в минуту
        if now - self._last_cleanup < 60:
            return

        self._last_cleanup = now
        cutoff = now - ENTRY_TTL_SECONDS

        # Удаляем пользователей без активности
        stale_keys = []
        for uid, timestamps in self._request_history.items():
            # Удаляем старые timestamp'ы
            recent = [ts for ts in timestamps if ts > cutoff]
            if recent:
                self._request_history[uid] = recent
            else:
                stale_keys.append(uid)

        for uid in stale_keys:
            del self._request_history[uid]

        if stale_keys:
            log.debug(f"[RateLimit] Cleaned up {len(stale_keys)} stale entries")

        # Аварийная очистка при переполнении
        if len(self._request_history) > MAX_RATE_LIMIT_ENTRIES:
            sorted_items = sorted(
                self._request_history.items(),
                key=lambda x: max(x[1]) if x[1] else 0
            )
            to_remove = len(self._request_history) - MAX_RATE_LIMIT_ENTRIES // 2
            for uid, _ in sorted_items[:to_remove]:
                del self._request_history[uid]
            log.warning(f"[RateLimit] Emergency cleanup: removed {to_remove} oldest entries")

    async def __call__(
        self,
        handler: Callable[[Update, Dict[str, Any]], Awaitable[Any]],
        event: Update,
        data: Dict[str, Any],
    ) -> Any:
        # Периодическая очистка устаревших записей
        self._cleanup_stale_entries()

        message: Message | None = None
        user_id: int | None = None

        if event.message:
            message = event.message
            if message.from_user is not None:
                user_id = message.from_user.id
        elif event.callback_query:
            # Для callback берём from_user у самого callback'а — это кликнувший юзер.
            # event.callback_query.message.from_user — это БОТ (отправитель кнопки).
            if event.callback_query.from_user is not None:
                user_id = event.callback_query.from_user.id
            message = event.callback_query.message

        if user_id is None:
            return await handler(event, data)

        text = (message.text if message else None) or ""
        lower = text.lower()

        # Команды, требующие rate limiting
        is_heavy_command = (
            lower.startswith("/scan")
            or lower.startswith("/phone")
            or lower.startswith("/bin")
            or lower.startswith("/url")
            or lower.startswith("/email")
            or lower.startswith("/ip")
            or lower.startswith("/user")
            or lower.startswith("/wallet")
            or lower.startswith("/leak")
            or lower.startswith("/qr")
        )

        # Фото и документы тоже требуют rate limiting (EXIF/QR сканы)
        is_media = bool(message) and (message.photo is not None or message.document is not None)

        # Обычный текст без команды — auto-detect (IP, домен, email, username)
        is_plain_text = bool(text) and not text.startswith("/")

        if not is_heavy_command and not is_media and not is_plain_text:
            return await handler(event, data)

        now = time.time()

        # Получаем историю запросов пользователя
        if user_id not in self._request_history:
            self._request_history[user_id] = []

        history = self._request_history[user_id]

        # Удаляем запросы старше окна
        history = [ts for ts in history if now - ts < self.window_seconds]
        self._request_history[user_id] = history

        # Проверяем burst limit
        if len(history) >= self.burst_limit:
            # Пользователь уже сделал много запросов, проверяем интервал
            last_request = history[-1]
            delta = now - last_request

            if delta < self.min_interval:
                wait = int(self.min_interval - delta) + 1
                if message is not None:
                    try:
                        await message.answer(
                            f"⏱ Слишком много запросов подряд.\n"
                            f"Подожди ещё {wait} сек перед следующим сканом."
                        )
                    except Exception:
                        pass
                log.info(f"[RateLimit] Blocked user_id={user_id} ({len(history)} requests in {self.window_seconds}s)")
                return

        # Добавляем текущий запрос в историю
        history.append(now)
        return await handler(event, data)
