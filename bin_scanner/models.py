# bin_scanner/models.py
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from utils.risk_types import RiskLevel, RiskFlag


class BinInfo(BaseModel):
    raw_input: str          # исходный ввод
    bin: str                # нормализованный BIN (цифры)

    scheme: Optional[str] = None       # visa/mastercard/...
    brand: Optional[str] = None        # Platinum/...
    card_type: Optional[str] = None    # debit/credit/prepaid/...
    bank_name: Optional[str] = None
    country_name: Optional[str] = None
    country_code: Optional[str] = None  # двухбуквенный код страны (RU, US, и т.д.)
    prepaid: Optional[bool] = None
    is_trusted: bool = False           # доверенный банк


class BinScanResult(BaseModel):
    bin: str
    info: Optional[BinInfo]

    risk_level: RiskLevel
    flags: List[RiskFlag]
    score: int = 0

    scanned_at: datetime
