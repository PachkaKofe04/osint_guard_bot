# bin_scanner/formatter.py
from typing import List

from utils.risk_types import RiskLevel, get_risk_emoji
from bin_scanner.models import BinScanResult


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
        return "Очень высокий уровень подозрительности по BIN."
    if score >= 6:
        return "Повышенный риск по BIN, стоит быть осторожнее."
    if score >= 4:
        return "Умеренный риск по BIN: есть отдельные настораживающие признаки."
    if score >= 2:
        return "Небольшой уровень риска по BIN."
    return "Явных проблем по этому BIN не видно."


def _score_for_view(score: int) -> int:
    if score < 0:
        return 0
    if score > 10:
        return 10
    return score


def format_bin_summary(result: BinScanResult) -> str:
    emoji = _risk_emoji(result.risk_level)
    human = _risk_human(result.risk_level)
    score_view = _score_for_view(result.score)
    comment = _score_comment(result.score)

    info = result.info

    lines: List[str] = []
    lines.append(f"{emoji} <b>Проверка BIN:</b> <code>{result.bin}</code>")
    lines.append(f"<b>Итоговый риск:</b> <b>{human}</b> ({score_view}/10)")
    lines.append(f"<b>Оценка:</b> {comment}")
    lines.append("")

    if info is None:
        lines.append("BIN не найден в открытой базе.")
    else:
        lines.append("<b>Данные по BIN:</b>")
        lines.append(f"  Схема: {info.scheme or '—'}")
        lines.append(f"  Бренд: {info.brand or '—'}")
        lines.append(f"  Тип карты: {info.card_type or '—'}")
        lines.append(f"  Банк: {info.bank_name or '—'}")
        if info.is_trusted:
            lines.append("  ✅ Доверенный банк")
        lines.append(f"  Страна: {info.country_name or '—'} ({info.country_code or '—'})")
        if info.prepaid is not None:
            lines.append(f"  Prepaid: {'да' if info.prepaid else 'нет'}")

    if result.flags:
        lines.append("")
        lines.append("<b>Детализация рисков:</b>")
        for f in result.flags[:5]:
            sign = "+" if f.weight >= 0 else ""
            lines.append(f"  {_flag_emoji(f.level)} ({sign}{f.weight}) {f.message}")

    return "\n".join(lines)
