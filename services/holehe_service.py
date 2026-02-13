# services/holehe_service.py
"""Holehe — проверка email на регистрацию в сервисах (100+ платформ)."""
import asyncio
import logging
from typing import List

log = logging.getLogger(__name__)


def _run_holehe_sync(email: str) -> List[str]:
    """
    Запускает holehe через trio в отдельном потоке.

    holehe использует trio (несовместим с asyncio напрямую),
    поэтому запускаем через asyncio.to_thread + trio.run.

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
            async with httpx.AsyncClient() as client:
                for website in websites:
                    out: List[dict] = []
                    await launch_module(website, email, client, out)
                    for item in out:
                        if item.get("exists"):
                            domain = item.get("domain") or item.get("name", "")
                            if domain:
                                found.append(domain)

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

    Запускает синхронный trio-код в отдельном потоке через asyncio.to_thread.

    Args:
        email: Email для проверки
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
