# states/scan_states.py
"""FSM-состояния сценария проверки."""
from aiogram.fsm.state import State, StatesGroup


class ScanStates(StatesGroup):
    """
    Одно состояние на все направления.

    Какое именно направление выбрано, хранится в данных FSM под ключом
    "direction". Двенадцать отдельных состояний ничего бы не дали: переходы
    у всех направлений одинаковые, отличаются только сканер и тексты.
    """

    waiting_input = State()


class MonitorStates(StatesGroup):
    """Добавление объекта в мониторинг через меню."""

    waiting_target = State()
