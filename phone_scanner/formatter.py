# phone_scanner/formatter.py
from typing import List

from utils.risk_types import RiskLevel, get_risk_emoji
from phone_scanner.models import PhoneScanResult


def _risk_emoji(level: RiskLevel) -> str:
    return get_risk_emoji(0 if level == RiskLevel.LOW else 5 if level == RiskLevel.MEDIUM else 8)


def _risk_human(level: RiskLevel) -> str:
    if level == RiskLevel.HIGH:
        return "Высокий"
    if level == RiskLevel.MEDIUM:
        return "Средний"
    return "Низкий"


def _flag_emoji(level: RiskLevel) -> str:
    return get_risk_emoji(0 if level == RiskLevel.LOW else 5 if level == RiskLevel.MEDIUM else 8)


def _score_comment(score: int) -> str:
    if score >= 8:
        return "Очень высокий уровень подозрительности, номер может быть использован в мошеннических целях."
    if score >= 6:
        return "Высокий уровень подозрительности, стоит осторожно относиться к звонкам/сообщениям с этого номера."
    if score >= 4:
        return "Умеренный риск: есть подозрительные признаки, но не критично."
    if score >= 2:
        return "Небольшой уровень риска: отдельные слабые признаки."
    return "Явных признаков недоброжелательности не выявлено."


def _score_for_view(score: int) -> int:
    if score < 0:
        return 0
    if score > 10:
        return 10
    return score


def format_phone_summary(result: PhoneScanResult) -> str:
    emoji = _risk_emoji(result.risk_level)
    human = _risk_human(result.risk_level)
    score_view = _score_for_view(result.score)
    comment = _score_comment(result.score)

    info = result.info
    country = info.country_code or "UNKNOWN"
    operator = info.operator or "не определён"
    region = info.region or "не определён"

    lines: List[str] = []
    lines.append(f"{emoji} <b>Проверка телефона:</b> <code>{result.phone}</code>")
    lines.append(f"<b>Итоговый риск:</b> <b>{human}</b> ({score_view}/10)")
    lines.append(f"<b>Уверенность:</b> {result.confidence}%")
    lines.append(f"<b>Страна (по номеру):</b> {country}")
    lines.append(f"<b>Оператор:</b> {operator}")
    if info.is_virtual:
        lines.append("  ⚠️ Виртуальный оператор (MVNO) — возможен MNP")
    lines.append(f"<b>Регион:</b> {region}")
    lines.append(f"<b>Оценка:</b> {comment}")

    if result.flags:
        lines.append("")
        lines.append("<b>Детализация рисков:</b>")
        for f in result.flags[:5]:
            sign = "+" if f.weight >= 0 else ""
            lines.append(f"  {_flag_emoji(f.level)} ({sign}{f.weight}) {f.message}")

    return "\n".join(lines)
