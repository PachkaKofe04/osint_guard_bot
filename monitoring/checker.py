# monitoring/checker.py
"""Логика проверки одного монитора и формирования уведомления."""
from __future__ import annotations

import logging
from typing import Optional, Tuple

from monitoring.models import MonitorEntry

log = logging.getLogger(__name__)


async def run_scan(entry: MonitorEntry) -> Optional[Tuple[str, int]]:
    """
    Запускает нужный сканер для entry.
    Возвращает (risk_level_str, score) или None при ошибке.
    """
    try:
        if entry.scan_type == "domain":
            from domain_scanner.scanner import scan_domain
            result = await scan_domain(entry.target)
            return result.risk_level.value, result.score

        elif entry.scan_type == "ip":
            from ip_scanner.scanner import scan_ip
            result = await scan_ip(entry.target)
            return result.risk_level.value, result.score

        elif entry.scan_type == "email":
            from email_scanner.scanner import scan_email
            result = await scan_email(entry.target)
            return result.risk_level.value, result.score

    except Exception as e:
        log.warning(f"[Monitor] Scan error for {entry.scan_type}:{entry.target}: {e}")

    return None


def build_alert_message(entry: MonitorEntry, new_level: str, new_score: int) -> Optional[str]:
    """
    Строит текст уведомления если что-то изменилось.
    Возвращает None если изменений нет.
    """
    old_level = entry.last_risk_level
    old_score = entry.last_score

    # Первая проверка — отправляем результат без сравнения
    if old_level is None:
        return _format_first_check(entry, new_level, new_score)

    level_changed = old_level != new_level
    score_changed = old_score is not None and abs(new_score - old_score) >= 2

    if not level_changed and not score_changed:
        return None  # ничего не изменилось — молчим

    return _format_change_alert(entry, old_level, old_score, new_level, new_score)


_LEVEL_EMOJI = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🔴",
    "CRITICAL": "🚨",
}

_TYPE_LABEL = {
    "domain": "домен",
    "ip": "IP",
    "email": "Email",
}


def _format_first_check(entry: MonitorEntry, level: str, score: int) -> str:
    emoji = _LEVEL_EMOJI.get(level, "⚪")
    type_label = _TYPE_LABEL.get(entry.scan_type, entry.scan_type)
    return (
        f"🔔 <b>Мониторинг запущен</b>\n"
        f"<b>Тип:</b> {type_label}\n"
        f"<b>Объект:</b> <code>{entry.target}</code>\n"
        f"\n"
        f"<b>Текущее состояние:</b>\n"
        f"{emoji} Уровень риска: <b>{level}</b> (оценка: {score}/10)\n"
        f"\n"
        f"<i>Бот уведомит тебя при изменении риска.</i>"
    )


def _format_change_alert(
    entry: MonitorEntry,
    old_level: str,
    old_score: Optional[int],
    new_level: str,
    new_score: int,
) -> str:
    old_emoji = _LEVEL_EMOJI.get(old_level, "⚪")
    new_emoji = _LEVEL_EMOJI.get(new_level, "⚪")
    type_label = _TYPE_LABEL.get(entry.scan_type, entry.scan_type)

    risk_went_up = _level_order(new_level) > _level_order(old_level)
    header = "⚠️ <b>Риск повысился!</b>" if risk_went_up else "✅ <b>Риск снизился</b>"

    score_line = ""
    if old_score is not None:
        score_line = f"\n<b>Оценка:</b> {old_score} → {new_score}/10"

    return (
        f"{header}\n"
        f"<b>Тип:</b> {type_label} | <code>{entry.target}</code>\n"
        f"\n"
        f"<b>Уровень риска:</b>\n"
        f"{old_emoji} {old_level} → {new_emoji} {new_level}"
        f"{score_line}\n"
        f"\n"
        f"<i>Используй соответствующую команду для полного скана.</i>"
    )


def _level_order(level: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(level, 0)
