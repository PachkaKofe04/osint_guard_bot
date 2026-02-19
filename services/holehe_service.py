# services/holehe_service.py
"""Holehe — проверка email на регистрацию в сервисах (100+ платформ)."""
import asyncio
import logging
from typing import List

log = logging.getLogger(__name__)

# Глушим httpx INFO-логи (holehe генерирует их сотнями)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


def _run_holehe_sync(email: str) -> List[str]:
    """
    Запускает holehe через trio в отдельном потоке.

    Все модули запускаются ПАРАЛЛЕЛЬНО через trio.open_nursery(),
    что сокращает время с ~3 мин до ~15-20 сек.

    Returns:
        Список доменов, на которых зарегистрирован email
    """
    try:
        import trio
        import httpx
        from holehe.core import import_submodules, get_functions, launch_module

        modules = import_submodules("holehe.modules")
        websites = get_functions(modules)

        found: List[str] = []

        async def _search() -> None:
            lock = trio.Lock()

            async def check_one(website) -> None:
                out: List[dict] = []
                try:
                    await launch_module(website, email, client, out)
                except Exception:
                    pass
                for item in out:
                    if item.get("exists"):
                        domain = item.get("domain") or item.get("name", "")
                        if domain:
                            async with lock:
                                found.append(domain)

            async with httpx.AsyncClient() as client:
                async with trio.open_nursery() as nursery:
                    for website in websites:
                        nursery.start_soon(check_one, website)

        trio.run(_search)
        return found

    except ImportError as e:
        log.warning(f"[Holehe] Не установлен пакет: {e}")
        return []
    except Exception as e:
        log.warning(f"[Holehe] Ошибка при поиске {email}: {e}")
        return []


async def check_holehe(email: str, timeout: int = 45) -> List[str]:
    """
    Async-обёртка для holehe.

    Args:
        email:   Email для проверки
        timeout: Максимальное время ожидания (секунды)

    Returns:
        Список доменов, где email зарегистрирован
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_holehe_sync, email),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        log.warning(f"[Holehe] Таймаут для {email}")
        return []
    except Exception as e:
        log.warning(f"[Holehe] Сбой для {email}: {e}")
        return []
