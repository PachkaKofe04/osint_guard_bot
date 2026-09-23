# utils/threat_flags.py
"""
Флаги риска по результату проверки в базах угроз.

Логика одинакова для домена, URL и IP, поэтому живёт в одном месте:
иначе три риск-движка разошлись бы в трактовке одного и того же вердикта.

Находка в базе - самый весомый сигнал из всех, что есть у бота. Это не
косвенный признак вроде молодого домена или скрытого WHOIS, а факт: объект
уже замечен за раздачей малвари, фишингом или работой в роли C2-сервера.
"""
from typing import List, Optional

from utils.risk_scoring import add_risk_flag
from utils.risk_types import RiskFlag, RiskLevel, ThreatVerdict

# Подтверждённая угроза должна давать максимум независимо от сигналов доверия:
# у боевого фишингового сайта бывает и валидный сертификат, и старый домен
THREAT_CONFIRMED = 10
# Проверка не выполнялась. Вес нулевой: это не риск, а неполнота проверки,
# но умолчать нельзя - иначе пользователь решит, что объект проверили
THREAT_UNKNOWN = 0


def _describe(verdict: ThreatVerdict) -> str:
    parts: List[str] = []

    if verdict.malware:
        parts.append(f"малварь: {verdict.malware}")

    if verdict.threat_type:
        readable = {
            "malware_download": "раздача вредоносного ПО",
            "payload_delivery": "доставка вредоносной нагрузки",
            "botnet_cc": "управляющий сервер ботнета",
            "botnet_c2": "управляющий сервер ботнета",
            "phishing": "фишинг",
        }.get(verdict.threat_type, verdict.threat_type)
        parts.append(readable)

    if verdict.confidence is not None:
        parts.append(f"уверенность {verdict.confidence}%")

    detail = ", ".join(parts) if parts else "числится в базах угроз"
    sources = ", ".join(verdict.sources) if verdict.sources else "база угроз"
    return f"Объект найден в базах угроз ({sources}): {detail}"


def add_threat_flags(
    flags: List[RiskFlag], verdict: Optional[ThreatVerdict]
) -> None:
    """
    Дописывает флаги по результату проверки в базах угроз.

    Ничего не делает, если проверка вообще не запускалась (verdict is None) -
    это случай старых вызовов, не знающих про базы.
    """
    if verdict is None:
        return

    if not verdict.checked:
        add_risk_flag(
            flags,
            "THREAT_DB_UNAVAILABLE",
            RiskLevel.MEDIUM,
            "Базы угроз недоступны - проверка по ним не выполнялась",
            THREAT_UNKNOWN,
        )
        return

    if verdict.found:
        add_risk_flag(
            flags,
            "KNOWN_THREAT",
            RiskLevel.HIGH,
            _describe(verdict),
            THREAT_CONFIRMED,
        )
        if verdict.tags:
            add_risk_flag(
                flags,
                "THREAT_TAGS",
                RiskLevel.MEDIUM,
                f"Метки угрозы: {', '.join(verdict.tags[:5])}",
                0,
            )
        return

    add_risk_flag(
        flags,
        "NOT_IN_THREAT_DB",
        RiskLevel.LOW,
        "В базах вредоносных и фишинговых объектов не числится",
        0,
    )
