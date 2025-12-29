# utils/retry.py
"""
Retry механизм для внешних API запросов.
"""
import asyncio
import logging
from typing import TypeVar, Callable, Any
from functools import wraps

log = logging.getLogger(__name__)

T = TypeVar('T')


def retry_sync(max_attempts: int = 3, backoff: float = 2.0, exceptions: tuple = (Exception,)):
    """
    Декоратор для повторных попыток синхронных функций.

    Args:
        max_attempts: Максимальное количество попыток
        backoff: Коэффициент экспоненциального отката (в секундах)
        exceptions: Кортеж исключений, при которых повторять попытку

    Example:
        @retry_sync(max_attempts=3, backoff=2)
        def fetch_data():
            return requests.get("https://api.example.com")
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        wait_time = backoff ** (attempt - 1)
                        log.warning(
                            f"[RETRY] {func.__name__} failed (attempt {attempt}/{max_attempts}): {e}. "
                            f"Retrying in {wait_time}s..."
                        )
                        import time
                        time.sleep(wait_time)
                    else:
                        log.error(
                            f"[RETRY] {func.__name__} failed after {max_attempts} attempts: {e}"
                        )
            raise last_exception
        return wrapper
    return decorator


def retry_async(max_attempts: int = 3, backoff: float = 2.0, exceptions: tuple = (Exception,)):
    """
    Декоратор для повторных попыток асинхронных функций.

    Args:
        max_attempts: Максимальное количество попыток
        backoff: Коэффициент экспоненциального отката (в секундах)
        exceptions: Кортеж исключений, при которых повторять попытку

    Example:
        @retry_async(max_attempts=3, backoff=2)
        async def fetch_data():
            return await aiohttp.get("https://api.example.com")
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        wait_time = backoff ** (attempt - 1)
                        log.warning(
                            f"[RETRY] {func.__name__} failed (attempt {attempt}/{max_attempts}): {e}. "
                            f"Retrying in {wait_time}s..."
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        log.error(
                            f"[RETRY] {func.__name__} failed after {max_attempts} attempts: {e}"
                        )
            raise last_exception
        return wrapper
    return decorator
