# handlers/monitor.py
"""Команды управления мониторингом: /monitor, /monitors, /unmonitor."""
import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from monitoring.models import MonitorEntry
from utils.safe_html import esc
from monitoring.storage import MonitorStorage, MAX_MONITORS_PER_USER
from utils.telegram_io import safe_answer

log = logging.getLogger(__name__)

router = Router()

# Единственный экземпляр хранилища - инициализируется снаружи
_storage: MonitorStorage | None = None


def set_storage(storage: MonitorStorage) -> None:
    global _storage
    _storage = storage


# Поддерживаемые типы сканирования для мониторинга
SUPPORTED_TYPES = {"domain", "ip", "email"}


def _detect_type(target: str) -> str | None:
    """Определяет тип цели по содержимому."""
    import re
    target = target.strip().lower()

    # IP
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_re.match(target):
        return "ip"

    # Email
    if "@" in target and "." in target.split("@")[-1]:
        return "email"

    # Домен (содержит точку, не email)
    if "." in target and not target.startswith("http"):
        return "domain"

    return None


@router.message(Command("monitor"))
async def cmd_monitor(message: Message) -> None:
    """
    /monitor <target> [domain|ip|email]

    Примеры:
      /monitor example.com
      /monitor 1.2.3.4
      /monitor user@example.com
    """
    if _storage is None:
        await safe_answer(message, "⚠️ Система мониторинга не инициализирована.")
        return

    parts = (message.text or "").split(maxsplit=2)

    if len(parts) < 2:
        await safe_answer(message,
            "📡 <b>Мониторинг</b>\n\n"
            "Использование: <code>/monitor &lt;объект&gt;</code>\n\n"
            "Примеры:\n"
            "  <code>/monitor example.com</code>\n"
            "  <code>/monitor 1.2.3.4</code>\n"
            "  <code>/monitor user@example.com</code>\n\n"
            f"Бот проверяет объект раз в 24 часа и уведомляет при изменении риска.\n"
            f"Лимит: {MAX_MONITORS_PER_USER} мониторов на пользователя."
        )
        return

    target = parts[1].strip().lower()

    # Тип: из аргумента или автодетект
    scan_type = parts[2].strip().lower() if len(parts) > 2 else None
    if scan_type and scan_type not in SUPPORTED_TYPES:
        await safe_answer(message, f"❌ Неизвестный тип: <code>{esc(scan_type)}</code>. Поддерживаются: domain, ip, email")
        return

    if not scan_type:
        scan_type = _detect_type(target)
        if not scan_type:
            await safe_answer(message,
                "❌ Не удалось определить тип объекта.\n"
                "Укажи тип явно: <code>/monitor example.com domain</code>"
            )
            return

    user_id = message.from_user.id
    entry = MonitorEntry(user_id=user_id, target=target, scan_type=scan_type)

    added = _storage.add(entry)
    if not added:
        existing = _storage.get(user_id, scan_type, target)
        if existing:
            await safe_answer(message, f"ℹ️ <code>{esc(target)}</code> уже в мониторинге.")
        else:
            await safe_answer(message,
                f"❌ Достигнут лимит мониторов ({MAX_MONITORS_PER_USER}).\n"
                "Удали один через /unmonitor перед добавлением нового."
            )
        return

    await safe_answer(message,
        f"✅ <b>Мониторинг добавлен</b>\n\n"
        f"<b>Объект:</b> <code>{esc(target)}</code>\n"
        f"<b>Тип:</b> {scan_type}\n\n"
        f"Первая проверка пройдёт в течение 5 минут.\n"
        f"Ты получишь уведомление при изменении уровня риска."
    )


@router.message(Command("monitors"))
async def cmd_monitors(message: Message) -> None:
    """/monitors - список активных мониторов пользователя."""
    if _storage is None:
        await safe_answer(message, "⚠️ Система мониторинга не инициализирована.")
        return

    user_id = message.from_user.id
    entries = _storage.list_for_user(user_id)

    if not entries:
        await safe_answer(message,
            "📡 У тебя нет активных мониторов.\n\n"
            "Добавить: <code>/monitor example.com</code>"
        )
        return

    _LEVEL_EMOJI = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}

    lines = [f"📡 <b>Активные мониторы ({len(entries)}/{MAX_MONITORS_PER_USER}):</b>\n"]
    for i, e in enumerate(entries, 1):
        level_part = ""
        if e.last_risk_level:
            emoji = _LEVEL_EMOJI.get(e.last_risk_level, "⚪")
            level_part = f" - {emoji} {e.last_risk_level}"
            if e.last_score is not None:
                level_part += f" ({e.last_score}/10)"

        lines.append(f"{i}. <code>{esc(e.target)}</code> [{e.scan_type}]{level_part}")

    lines.append("\n<i>Удалить: /unmonitor example.com</i>")
    await safe_answer(message, "\n".join(lines))


@router.message(Command("unmonitor"))
async def cmd_unmonitor(message: Message) -> None:
    """/unmonitor <target> - остановить мониторинг объекта."""
    if _storage is None:
        await safe_answer(message, "⚠️ Система мониторинга не инициализирована.")
        return

    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await safe_answer(message, "Использование: <code>/unmonitor example.com</code>")
        return

    target = parts[1].strip().lower()
    user_id = message.from_user.id

    # Ищем монитор для этой цели (по любому типу)
    removed = False
    for scan_type in SUPPORTED_TYPES:
        if _storage.remove(user_id, scan_type, target):
            removed = True
            break

    if removed:
        await safe_answer(message, f"✅ Мониторинг <code>{esc(target)}</code> остановлен.")
    else:
        await safe_answer(message,
            f"❌ Монитор <code>{esc(target)}</code> не найден.\n"
            "Проверь список: /monitors"
        )
