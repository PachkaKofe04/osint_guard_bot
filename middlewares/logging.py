# middlewares/logging.py
import logging
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import Update

log = logging.getLogger(__name__)


class LoggingMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[Update, Dict[str, Any]], Awaitable[Any]],
        event: Update,
        data: Dict[str, Any],
    ) -> Any:
        try:
            user = None
            if event.message and event.message.from_user:
                user = event.message.from_user
            elif event.callback_query and event.callback_query.from_user:
                user = event.callback_query.from_user

            if user:
                log.info(f"Update from user_id=%s username=%s", user.id, user.username)

            return await handler(event, data)
        except Exception:
            log.exception("Error while processing update")
            raise
