# middlewares/rate_limit.py
import time
import logging
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import Update, Message

log = logging.getLogger(__name__)


class RateLimitMiddleware(BaseMiddleware):
    """
    Простой rate limit:
    - для /scan, /phone, /bin не чаще, чем раз N секунд на пользователя
    """

    def __init__(self, min_interval_seconds: int = 10) -> None:
        super().__init__()
        self.min_interval = min_interval_seconds
        self._last_call: Dict[int, float] = {}

    async def __call__(
        self,
        handler: Callable[[Update, Dict[str, Any]], Awaitable[Any]],
        event: Update,
        data: Dict[str, Any],
    ) -> Any:
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

        is_heavy_command = (
            lower.startswith("/scan")
            or lower.startswith("/phone")
            or lower.startswith("/bin")
        )

        if not is_heavy_command:
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
