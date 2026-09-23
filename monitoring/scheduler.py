# monitoring/scheduler.py
"""Фоновая задача периодической проверки всех активных мониторов."""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from monitoring.checker import build_alert_message, run_scan

if TYPE_CHECKING:
    from aiogram import Bot
    from monitoring.storage import MonitorStorage

log = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = 300  # проверяем список "просроченных" каждые 5 минут


async def monitor_loop(bot: "Bot", storage: "MonitorStorage") -> None:
    """
    Бесконечный цикл: каждые CHECK_INTERVAL_SECONDS секунд проверяет
    все мониторы у которых вышло время, запускает скан и отправляет уведомление.
    """
    log.info("[Monitor] Scheduler started")

    while True:
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)

        due = storage.all_due()
        if not due:
            continue

        log.info(f"[Monitor] Checking {len(due)} due monitors")

        for entry in due:
            result = await run_scan(entry)
            if result is None:
                # Не удалось проверить - обновляем last_checked чтобы не спамить
                import time
                entry.last_checked_at = time.time()
                storage.save()
                continue

            new_level, new_score = result
            alert = build_alert_message(entry, new_level, new_score)

            # Обновляем состояние в хранилище
            storage.update_result(entry.key, new_level, new_score)

            if alert:
                try:
                    await bot.send_message(
                        entry.user_id,
                        alert,
                        parse_mode="HTML",
                    )
                    log.info(f"[Monitor] Alert sent to user_id={entry.user_id} for {entry.target}")
                except Exception as e:
                    log.warning(f"[Monitor] Failed to send alert to {entry.user_id}: {e}")

            # Небольшая пауза между сканами чтобы не перегружать внешние API
            await asyncio.sleep(2)

    log.info("[Monitor] Scheduler stopped")
