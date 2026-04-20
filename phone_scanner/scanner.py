# phone_scanner/scanner.py
"""
Сканер телефонных номеров.
Основной источник: phonenumbers (Google libphonenumber, бесплатно, оффлайн).
Опциональный апгрейд: Veriphone API (если VERIPHONE_API_KEY задан в .env).
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import phonenumbers
from phonenumbers import geocoder, carrier as pn_carrier, PhoneNumberType

from config import settings
from phone_scanner.models import PhoneInfo, PhoneScanResult
from phone_scanner.risk_engine import calculate_phone_risk
from services.veriphone_service import verify_phone_veriphone
from utils.cache import TTLCache

log = logging.getLogger(__name__)

_phone_cache: TTLCache[PhoneScanResult] = TTLCache(ttl_seconds=600, max_size=1024)

# Маппинг типов phonenumbers → человекочитаемое + флаг виртуальности
_TYPE_LABELS = {
    PhoneNumberType.MOBILE:              ("Мобильный", False),
    PhoneNumberType.FIXED_LINE:          ("Стационарный", False),
    PhoneNumberType.FIXED_LINE_OR_MOBILE:("Мобильный/Стационарный", False),
    PhoneNumberType.VOIP:                ("VoIP (виртуальный)", True),
    PhoneNumberType.PREMIUM_RATE:        ("Платный (premium)", True),
    PhoneNumberType.TOLL_FREE:           ("Бесплатный 800", False),
    PhoneNumberType.SHARED_COST:         ("Общая стоимость", False),
    PhoneNumberType.PERSONAL_NUMBER:     ("Персональный", False),
    PhoneNumberType.PAGER:               ("Пейджер", False),
    PhoneNumberType.UAN:                 ("Единый номер (UAN)", False),
}


def normalize_phone(raw: str) -> str:
    """
    Нормализовать телефонный номер до строки цифр.

    Примеры:
        8(999)585-20-48  -> 79995852048
        +7 999 585 20 48 -> 79995852048
        9995852048       -> 79995852048
    """
    cleaned = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    digits = "".join(ch for ch in cleaned if ch.isdigit())

    # RU: 8XXXXXXXXXX → 7XXXXXXXXXX
    if digits.startswith("8") and len(digits) == 11:
        digits = "7" + digits[1:]

    # 10 цифр без кода страны — предполагаем РФ
    if len(digits) == 10 and not digits.startswith(("7", "3", "8", "1")):
        digits = "7" + digits

    return digits


def _parse_with_phonenumbers(phone_e164: str) -> Optional[PhoneInfo]:
    """
    Разбирает номер через библиотеку phonenumbers (Google libphonenumber).
    Возвращает PhoneInfo или None если номер невалиден.
    """
    try:
        parsed = phonenumbers.parse(phone_e164, None)
    except phonenumbers.NumberParseException:
        return None

    if not phonenumbers.is_valid_number(parsed):
        return None

    # Страна
    country_code = phonenumbers.region_code_for_number(parsed) or "UNKNOWN"

    # Регион/город (на русском если доступно, иначе английский)
    region = (
        geocoder.description_for_number(parsed, "ru")
        or geocoder.description_for_number(parsed, "en")
        or None
    )

    # Оператор по префиксу (оффлайн база — НЕ учитывает перенос номера MNP)
    carrier_name = (
        pn_carrier.name_for_number(parsed, "ru")
        or pn_carrier.name_for_number(parsed, "en")
        or None
    )

    # Тип линии
    num_type = phonenumbers.number_type(parsed)
    type_label, is_virtual = _TYPE_LABELS.get(num_type, ("Неизвестный", False))

    # Национальный номер
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

    return PhoneInfo(
        raw_input=phone_e164,
        normalized=phone_e164.lstrip("+"),
        country_code=country_code,
        national_number=national,
        length=len(phone_e164.lstrip("+")),
        operator=carrier_name,
        region=region if region else None,
        is_virtual=is_virtual,
        confidence=85,  # оффлайн база — высокая точность для страны/типа, ниже для оператора
    )


async def scan_phone(raw_phone: str) -> PhoneScanResult:
    """
    Сканирование телефонного номера.

    1. phonenumbers — страна, тип, оператор (по префиксу), регион
    2. Veriphone API (если ключ задан) — апгрейд: точный оператор с учётом MNO-данных
    """
    normalized = normalize_phone(raw_phone)
    phone_e164 = f"+{normalized}"

    cached = _phone_cache.get(normalized)
    if cached is not None:
        return cached

    log.info(f"[PHONE] Scanning: {phone_e164}")

    # --- Шаг 1: phonenumbers (бесплатно, всегда) ---
    phone_info = _parse_with_phonenumbers(phone_e164)

    if phone_info is None:
        # Номер невалиден по libphonenumber
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
    else:
        phone_info.raw_input = raw_phone.strip()

    # --- Шаг 2: Veriphone API (опционально, если ключ задан) ---
    api_key = settings.VERIPHONE_API_KEY
    if api_key and phone_info.confidence > 0:
        api_data = await verify_phone_veriphone(phone_e164, api_key)
        if api_data and api_data.get("phone_valid"):
            # Обновляем только теми полями, которые Veriphone знает лучше
            if api_data.get("carrier"):
                phone_info.operator = api_data["carrier"]
            if api_data.get("phone_region"):
                phone_info.region = api_data["phone_region"]
            phone_type = api_data.get("phone_type", "")
            if phone_type in ("voip", "premium_rate"):
                phone_info.is_virtual = True
            phone_info.confidence = 95
            log.info(f"[PHONE] Veriphone upgrade: carrier={phone_info.operator}")

    # --- Риск ---
    risk_level, flags, score, confidence = calculate_phone_risk(phone_info)

    result = PhoneScanResult(
        phone=raw_phone.strip(),
        info=phone_info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        confidence=phone_info.confidence,
        scanned_at=datetime.now(timezone.utc),
    )

    _phone_cache.set(normalized, result)
    return result
