# services/maigret_service.py
"""Maigret — углублённый поиск username по 2000+ платформам."""
import asyncio
import logging
import os
from typing import List, Tuple

log = logging.getLogger(__name__)

# Максимальное число сайтов за один запрос (баланс скорости и охвата)
DEFAULT_MAX_SITES = 500
DEFAULT_TIMEOUT = 90


async def maigret_search(
    username: str,
    max_sites: int = DEFAULT_MAX_SITES,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[List[Tuple[str, str]], int]:
    """
    Ищет username через Maigret по топ-N платформам.

    Args:
        username:  Username для поиска
        max_sites: Максимальное число сайтов (ограничиваем для скорости)
        timeout:   Общий таймаут в секундах

    Returns:
        Tuple:
            - list of (site_name, profile_url) — найденные профили
            - int — сколько всего проверено сайтов
    """
    try:
        import maigret as maigret_pkg
        from maigret import search, MaigretDatabase
        from maigret.result import MaigretCheckStatus

        # Путь к базе данных сайтов внутри пакета
        db_path = os.path.join(
            os.path.dirname(maigret_pkg.__file__), "resources", "data.json"
        )

        db = MaigretDatabase().load_from_file(db_path)

        # Ограничиваем набор сайтов для контролируемой скорости
        all_sites = db.sites_dict
        site_dict = dict(list(all_sites.items())[:max_sites])
        total_checked = len(site_dict)

        # Глушим логи maigret (он очень разговорчив)
        maigret_logger = logging.getLogger("maigret")
        maigret_logger.setLevel(logging.CRITICAL)

        results = await asyncio.wait_for(
            search(
                username,
                site_dict,
                maigret_logger,
                no_progressbar=True,
                timeout=5,         # per-site timeout
                max_connections=50,
            ),
            timeout=timeout,
        )

        found: List[Tuple[str, str]] = []

        # maigret возвращает {site_name: dict} где dict["status"] = MaigretCheckResult объект
        # MaigretCheckResult.status — это MaigretCheckStatus enum (CLAIMED/AVAILABLE/...)
        for site_name, result in results.items():
            if isinstance(result, dict):
                check = result.get("status")     # MaigretCheckResult объект
                url = result.get("url_user", "") or ""
            else:
                # fallback: прямой MaigretCheckResult
                check = result
                url = getattr(result, "site_url_user", "") or ""

            if check is None:
                continue

            status = getattr(check, "status", None)
            if status == MaigretCheckStatus.CLAIMED:
                found.append((site_name, url))

        log.info(f"[Maigret] {username}: найден на {len(found)}/{total_checked} платформах")
        return found, total_checked

    except asyncio.TimeoutError:
        log.warning(f"[Maigret] Таймаут для {username}")
        return [], 0
    except ImportError as e:
        log.warning(f"[Maigret] Не установлен пакет: {e}")
        return [], 0
    except Exception as e:
        log.warning(f"[Maigret] Ошибка для {username}: {e}")
        return [], 0
