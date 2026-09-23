# middlewares/rate_limit.py
import logging
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from aiogram import BaseMiddleware
from aiogram.types import Message, Update

from config import settings
from utils.input_detect import triggers_scan

log = logging.getLogger(__name__)

# Максимальное количество записей в кэше rate limit
MAX_RATE_LIMIT_ENTRIES = 10000
# Время жизни записи (в секундах) — после этого запись считается устаревшей
ENTRY_TTL_SECONDS = 3600  # 1 час

# Команды, которые ходят во внешние API. Лимитируются только с аргументом:
# голое «/ip» печатает подсказку и никуда не ходит — квоту тратить незачем.
SCAN_COMMANDS = {
    "/scan", "/domain", "/phone", "/bin", "/url", "/email", "/ip",
    "/user", "/username", "/wallet", "/leak", "/qr", "/monitor",
}


class RateLimitMiddleware(BaseMiddleware):
    """
    Rate limit с burst allowance.

    Лимитируются ТОЛЬКО сообщения, реально порождающие обращения к внешним API:
      - команда из SCAN_COMMANDS с аргументом;
      - фото или документ (EXIF/QR);
      - произвольный текст, который авто-детект опознал как цель скана.

    Не лимитируются:
      - нажатия inline-кнопок (callback_query) — это дешёвый edit_text.
        Раньше они попадали в квоту, и меню умирало после 5 кликов;
      - usage-подсказки («/ip» без аргумента);
      - обычная переписка, на которую бот не запускает скан.
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

        stale_keys = []
        for uid, timestamps in self._request_history.items():
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

    @staticmethod
    def _is_scan_request(message: Message) -> bool:
        """Породит ли это сообщение реальное обращение к внешним API."""
        # Медиа всегда идёт в сканер (EXIF или QR)
        if message.photo or message.document:
            return True

        text = (message.text or "").strip()
        if not text:
            return False

        if text.startswith("/"):
            parts = text.split(maxsplit=1)
            command = parts[0].split("@", 1)[0].lower()
            has_argument = len(parts) > 1 and bool(parts[1].strip())
            return command in SCAN_COMMANDS and has_argument

        return triggers_scan(text)

    async def __call__(
        self,
        handler: Callable[[Update, Dict[str, Any]], Awaitable[Any]],
        event: Update,
        data: Dict[str, Any],
    ) -> Any:
        self._cleanup_stale_entries()

        # Нажатия кнопок не лимитируем: это навигация, а не скан.
        if event.callback_query is not None:
            return await handler(event, data)

        message: Optional[Message] = event.message or event.edited_message
        if message is None or message.from_user is None:
            return await handler(event, data)

        user_id = message.from_user.id

        # Администраторы не ограничены rate limit
        if user_id in settings.ADMIN_IDS:
            return await handler(event, data)

        if not self._is_scan_request(message):
            return await handler(event, data)

        now = time.time()

        history = self._request_history.setdefault(user_id, [])
        # Удаляем запросы старше окна
        history = [ts for ts in history if now - ts < self.window_seconds]
        self._request_history[user_id] = history

        if len(history) >= self.burst_limit:
            delta = now - history[-1]
            if delta < self.min_interval:
                wait = int(self.min_interval - delta) + 1
                try:
                    await message.answer(
                        f"⏱ Слишком много проверок подряд.\n"
                        f"Подожди ещё {wait} сек перед следующим сканом."
                    )
                except Exception:
                    log.debug("[RateLimit] Не удалось отправить уведомление о лимите")
                log.info(
                    f"[RateLimit] Blocked user_id={user_id} "
                    f"({len(history)} scans in {self.window_seconds}s)"
                )
                return

        history.append(now)
        return await handler(event, data)
