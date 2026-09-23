# wallet_scanner/models.py
"""Модели данных для Crypto Wallet сканера."""
from datetime import datetime
from typing import List, Optional
from decimal import Decimal
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel


class WalletInfo(BaseModel):
    """Полная информация о криптокошельке."""
    address: str
    currency: str  # BTC, ETH, USDT, etc.

    # Валидация
    is_valid: bool = True

    # Баланс
    balance: Optional[Decimal] = None
    balance_usd: Optional[Decimal] = None

    # Активность
    tx_count: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Репутация
    is_scam: bool = False
    scam_reports: int = 0
    scam_labels: List[str] = []  # Метки: phishing, scam, hack, etc.

    # Была ли скам-проверка выполнена на самом деле.
    # Без этого поля недоступная база превращалась в вердикт «скам не обнаружен»:
    # бот уверенно говорил «чисто», хотя не проверял ничего.
    scam_check_performed: bool = False

    # Возможно ли получить баланс для этой монеты в принципе.
    # Для Monero - нет: протокол не раскрывает балансы по адресу.
    balance_available: bool = True
    # Откуда взяты данные блокчейна: mempool.space, Blockscout, BlockCypher, ...
    data_source: Optional[str] = None

    # Связанные сервисы
    exchange_name: Optional[str] = None  # Если адрес принадлежит бирже
    is_contract: bool = False  # Для ETH - смарт-контракт
    # Обычный кошелёк с делегированием EIP-7702 на смарт-аккаунт.
    # Blockscout помечает такие как контракты, но для пользователя это
    # не контракт, а его личный кошелёк с расширенными возможностями.
    is_smart_account: bool = False
    contract_name: Optional[str] = None


class WalletScanResult(BaseModel):
    """Результат сканирования кошелька."""
    address: str
    currency: str
    info: Optional[WalletInfo] = None
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
    from_cache: bool = False
