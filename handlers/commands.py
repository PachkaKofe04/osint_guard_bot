# handlers/commands.py
"""
Команды-алиасы к направлениям проверки.

Команды остаются для тех, кому так быстрее, но собственной логики у них нет:
они ведут в тот же сценарий, что и кнопки меню.

    /ip 8.8.8.8   - проверяет сразу
    /ip           - открывает тот же экран ввода, что и кнопка «IP-адрес»

Раньше на каждое направление был отдельный файл-хендлер с собственными
текстами ошибок и собственным поведением при пустом аргументе. Семь копий
расходились между собой и с кнопочным сценарием.
"""
from __future__ import annotations

import logging

from aiogram import Router, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext

from handlers.scan_flow import start_direction, run_direction
from scan_registry import DIRECTIONS, INPUT_IMAGE, Direction

log = logging.getLogger(__name__)

router = Router()


def _make_command_handler(direction: Direction):
    """Собирает хендлер команды для конкретного направления."""

    async def handler(message: types.Message, state: FSMContext) -> None:
        parts = (message.text or "").split(maxsplit=1)
        argument = parts[1].strip() if len(parts) > 1 else ""

        # Без аргумента или когда нужен файл - переводим в режим ожидания ввода
        if not argument or direction.input_kind == INPUT_IMAGE:
            await start_direction(message, direction, state)
            return

        await state.clear()
        await run_direction(message, direction, argument, None)

    handler.__name__ = f"cmd_{direction.key}"
    handler.__doc__ = f"Команда-алиас для направления «{direction.title}»."
    return handler


def _register() -> None:
    """Регистрирует по одному хендлеру на направление с командами."""
    for direction in DIRECTIONS.values():
        if not direction.commands:
            continue
        names = [c.lstrip("/") for c in direction.commands]
        router.message(Command(*names))(_make_command_handler(direction))
        log.debug("[commands] %s -> %s", direction.key, ", ".join(direction.commands))


_register()
