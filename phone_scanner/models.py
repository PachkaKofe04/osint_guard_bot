# phone_scanner/models.py
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from utils.risk_types import RiskLevel, RiskFlag


class PhoneInfo(BaseModel):
    raw_input: str
    normalized: str          # только цифры
    country_code: Optional[str] = None  # например: "RU", "UA", "KZ", "UNKNOWN"
    national_number: Optional[str] = None
    length: int = 0

    operator: Optional[str] = None      # оператор связи (если удалось определить)
    region: Optional[str] = None        # регион (очень грубо, по префиксу)
    is_virtual: bool = False            # MNP/виртуальный оператор
    confidence: int = 100               # уровень уверенности в определении (0-100%)


class PhoneScanResult(BaseModel):
    phone: str
    info: PhoneInfo

    risk_level: RiskLevel
    flags: List[RiskFlag]
    score: int = 0
    confidence: int = 100

    scanned_at: datetime
