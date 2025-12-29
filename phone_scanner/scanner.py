# phone_scanner/scanner.py
"""
Сканер телефонных номеров через Veriphone API.
Использует Veriphone для получения точной информации о номере.
"""
import logging
import os
from datetime import datetime
from typing import Optional

from phone_scanner.models import PhoneInfo, PhoneScanResult
from phone_scanner.risk_engine import calculate_phone_risk
from services.veriphone_service import verify_phone_veriphone

log = logging.getLogger(__name__)


def normalize_phone(raw: str) -> str:
    """
    Нормализовать телефонный номер.

    Примеры:
        8(999)585-20-48 -> 79995852048
        +7 999 585 20 48 -> 79995852048
        9995852048 -> 79995852048
        +1 415 200 7986 -> 14152007986
    """
    # Удаляем всё кроме цифр и +
    cleaned = "".join(ch for ch in raw if ch.isdigit() or ch == "+")

    # Убираем + в начале
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]

    # Только цифры
    digits = "".join(ch for ch in cleaned if ch.isdigit())

    # RU: 8XXXXXXXXXX -> 7XXXXXXXXXX
    if digits.startswith("8") and len(digits) == 11:
        digits = "7" + digits[1:]

    # Если просто 10 цифр РФ без 7/8
    if len(digits) == 10 and not digits.startswith(("7", "3", "8", "1")):
        digits = "7" + digits

    return digits


async def scan_phone(raw_phone: str) -> PhoneScanResult:
    """
    Сканирование телефонного номера через Veriphone API.

    Args:
        raw_phone: Телефонный номер в любом формате

    Returns:
        PhoneScanResult с полной информацией и оценкой риска

    Environment:
        VERIPHONE_API_KEY - API ключ для Veriphone
    """
    normalized = normalize_phone(raw_phone)
    api_key = os.getenv("VERIPHONE_API_KEY")

    # Если API ключ не установлен
    if not api_key:
        log.warning("[PHONE] VERIPHONE_API_KEY not set, returning minimal info")
        phone_info = PhoneInfo(
            raw_input=raw_phone.strip(),
            normalized=normalized,
            country_code="UNKNOWN",
            national_number=normalized,
            length=len(normalized),
            operator=None,
            region=None,
            is_virtual=False,
            confidence=0,
        )

        risk_level, flags, score, confidence = calculate_phone_risk(phone_info)

        return PhoneScanResult(
            phone=raw_phone.strip(),
            info=phone_info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            confidence=0,
            scanned_at=datetime.utcnow(),
        )

    # Получаем данные через Veriphone API
    # Veriphone требует номер с +
    phone_with_plus = f"+{normalized}"
    api_data = await verify_phone_veriphone(phone_with_plus, api_key)

    if not api_data:
        log.warning(f"[PHONE] API request failed for {normalized}")
        phone_info = PhoneInfo(
            raw_input=raw_phone.strip(),
            normalized=normalized,
            country_code="UNKNOWN",
            national_number=normalized,
            length=len(normalized),
            operator=None,
            region=None,
            is_virtual=False,
            confidence=50,
        )
    else:
        # Парсим ответ от Veriphone
        valid = api_data.get("phone_valid", False)
        country_code = api_data.get("country_code", "UNKNOWN")
        country_name = api_data.get("country", "Unknown")
        carrier = api_data.get("carrier")
        location = api_data.get("phone_region")
        phone_type = api_data.get("phone_type")  # mobile/fixed_line/voip

        # Определяем is_virtual (VOIP, виртуальные номера)
        is_virt = phone_type in ("voip", "premium_rate", "toll_free")

        # Confidence на основе valid
        confidence = 95 if valid else 60

        phone_info = PhoneInfo(
            raw_input=raw_phone.strip(),
            normalized=normalized,
            country_code=country_code,
            national_number=normalized,
            length=len(normalized),
            operator=carrier,
            region=location,
            is_virtual=is_virt,
            confidence=confidence,
        )

        log.info(
            f"[PHONE] {raw_phone} → valid={valid}, country={country_code}, "
            f"carrier={carrier}, location={location}, type={phone_type}"
        )

    # Рассчитываем риск
    risk_level, flags, score, confidence = calculate_phone_risk(phone_info)

    result = PhoneScanResult(
        phone=raw_phone.strip(),
        info=phone_info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        confidence=confidence,
        scanned_at=datetime.utcnow(),
    )

    return result
