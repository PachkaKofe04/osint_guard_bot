# states/qr_states.py
"""FSM states для сканирования QR кодов."""
from aiogram.fsm.state import State, StatesGroup


class QRScanStates(StatesGroup):
    """Состояния для процесса сканирования QR."""
    waiting_for_photo = State()
