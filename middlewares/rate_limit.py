# middlewares/rate_limit.py
import time
import logging
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import Update, Message

log = logging.getLogger(__name__)

# Максимальное количество записей в кэше rate limit
MAX_RATE_LIMIT_ENTRIES = 10000
# Время жизни записи (в секундах) — после этого запись считается устаревшей
ENTRY_TTL_SECONDS = 3600  # 1 час


class RateLimitMiddleware(BaseMiddleware):
    """
    Простой rate limit:
    - для /scan, /phone, /bin не чаще, чем раз N секунд на пользователя
    - автоматическая очистка устаревших записей для предотвращения утечки памяти
    """

    def __init__(self, min_interval_seconds: int = 10) -> None:
        super().__init__()
        self.min_interval = min_interval_seconds
        self._last_call: Dict[int, float] = {}
        self._last_cleanup: float = time.time()

    def _cleanup_stale_entries(self) -> None:
        """Удаляет устаревшие записи из словаря."""
        now = time.time()
        # Очистка не чаще раза в минуту
        if now - self._last_cleanup < 60:
            return

        self._last_cleanup = now
        cutoff = now - ENTRY_TTL_SECONDS
        stale_keys = [uid for uid, ts in self._last_call.items() if ts < cutoff]

        for uid in stale_keys:
            del self._last_call[uid]

        if stale_keys:
            log.debug(f"[RateLimit] Cleaned up {len(stale_keys)} stale entries")

        # Аварийная очистка при переполнении
        if len(self._last_call) > MAX_RATE_LIMIT_ENTRIES:
            sorted_items = sorted(self._last_call.items(), key=lambda x: x[1])
            to_remove = len(self._last_call) - MAX_RATE_LIMIT_ENTRIES // 2
            for uid, _ in sorted_items[:to_remove]:
                del self._last_call[uid]
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

        if event.message:
            message = event.message
        elif event.callback_query and event.callback_query.message:
            message = event.callback_query.message

        if message is None or message.from_user is None:
            return await handler(event, data)

        user_id = message.from_user.id

        text = message.text or ""
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
        is_media = message.photo is not None or message.document is not None

        if not is_heavy_command and not is_media:
            return await handler(event, data)

        now = time.time()
        last = self._last_call.get(user_id, 0.0)
        delta = now - last

        if delta < self.min_interval:
            wait = int(self.min_interval - delta) + 1
            try:
                await message.answer(
                    f"Ты слишком часто отправляешь запросы. "
                    f"Подожди ещё {wait} сек перед следующим сканом."
                )
            except Exception:
                pass
            log.info("Rate limited user_id=%s", user_id)
            return

        self._last_call[user_id] = now
        return await handler(event, data)
