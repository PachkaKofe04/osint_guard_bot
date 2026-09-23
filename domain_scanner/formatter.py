# domain_scanner/formatter.py
from utils.safe_html import esc
from typing import List

from domain_scanner.models import DomainScanResult
from utils.risk_types import RiskLevel, RiskFlag, get_risk_emoji


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
    """
    Шкала 0-10: чем больше, тем подозрительнее.
    """
    if score >= 9:
        return "Максимальная подозрительность. Очень похоже на фишинг/скам."
    if score >= 8:
        return "Очень высокий уровень подозрительности, стоит максимально осторожно относиться к сайту."
    if score >= 6:
        return "Высокий уровень подозрительности, перед любыми действиями лучше проверить сайт вручную."
    if score >= 4:
        return "Умеренный риск: есть сомнительные признаки. Нужна дополнительная проверка."
    if score >= 2:
        return "Небольшой уровень риска: единичные слабые признаки."
    return "Явных признаков недоброжелательности не выявлено."


def _score_for_view(score: int) -> int:
    # показываем 0..10
    if score < 0:
        return 0
    if score > 10:
        return 10
    return score


def format_summary(result: DomainScanResult) -> str:
    emoji = _risk_emoji(result.risk_level)
    human = _risk_human(result.risk_level)
    score_view = _score_for_view(result.score)
    comment = _score_comment(result.score)

    top_flags: List[RiskFlag] = result.flags[:3]
    if top_flags:
        flags_str = "\n".join(
            f"{_flag_emoji(f.level)} ({'+' if f.weight >= 0 else ''}{f.weight}) {esc(f.message)}"
            for f in top_flags
        )
    else:
        flags_str = "Подозрительных признаков не выявлено."

    cache_note = " (из кэша)" if result.from_cache else ""

    text = (
        f"{emoji} <b>Сканирование домена:</b> <code>{esc(result.normalized_domain)}</code>{cache_note}\n"
        f"<b>Итоговый риск:</b> <b>{human}</b> ({score_view}/10)\n"
        f"<b>Оценка:</b> {comment}\n\n"
        f"<b>Основные признаки:</b>\n{flags_str}"
    )
    return text


def format_details(result: DomainScanResult) -> str:
    lines: List[str] = []

    emoji = _risk_emoji(result.risk_level)
    human = _risk_human(result.risk_level)
    score_view = _score_for_view(result.score)
    comment = _score_comment(result.score)

    lines.append(f"{emoji} <b>Подробный отчёт по домену</b> <code>{esc(result.normalized_domain)}</code>")
    lines.append(f"<b>Итоговый риск:</b> <b>{human}</b> ({score_view}/10)")
    lines.append(f"<b>Оценка:</b> {comment}")
    lines.append("")

    # WHOIS
    w = result.whois
    lines.append("<b>WHOIS</b>")
    if w is None:
        lines.append("  Не удалось получить WHOIS-данные.")
    else:
        lines.append(f"  Дата регистрации: {esc(w.creation_date or '-')}")
        lines.append(f"  Последнее обновление: {esc(w.updated_date or '-')}")
        lines.append(f"  Регистратор: {esc(w.registrar or '-')}")
        lines.append(f"  Страна: {esc(w.country or '-')}")
        lines.append(f"  Приватность WHOIS: {'да' if w.is_privacy_protected else 'нет'}")
    lines.append("")

    # DNS
    d = result.dns
    lines.append("<b>DNS</b>")
    if d is None:
        lines.append("  Не удалось получить DNS-записи.")
    else:
        lines.append(f"  A: {esc(', '.join(d.a_records) or '-')}")
        lines.append(f"  NS: {esc(', '.join(d.ns_records) or '-')}")
        lines.append(f"  MX: {esc(', '.join(d.mx_records) or '-')}")
        lines.append(f"  TXT: {esc(', '.join(d.txt_records) or '-')}")
    lines.append("")

    # IP / Hosting enrichment
    lines.append("<b>IP / Hosting</b>")
    if not result.ip_profiles:
        lines.append("  Нет данных по IP.")
    else:
        for p in result.ip_profiles[:5]:
            lines.append(f"  IP: {esc(p.ip)}")
            lines.append(f"    Страна/город: {esc((p.country or '-'))} / {esc((p.city or '-'))}")
            lines.append(f"    ISP/ORG: {esc((p.isp or '-'))} / {esc((p.org or '-'))}")
            lines.append(f"    ASN: {esc((p.asn or '-'))} ({esc(p.asname or '-')})")
            if p.proxy is not None:
                lines.append(f"    Proxy/VPN: {'да' if p.proxy else 'нет'}")
            if p.hosting is not None:
                lines.append(f"    Hosting/VPS: {'да' if p.hosting else 'нет'}")
    lines.append("")

    # OTX Reputation
    if result.otx:
        lines.append("<b>AlienVault OTX</b>")
        if result.otx.pulse_count > 0:
            lines.append(f"  Угрозы: {result.otx.pulse_count}")
        else:
            lines.append("  Угрозы: не обнаружены")
        if result.otx.malware_samples > 0:
            lines.append(f"  Malware образцы: {result.otx.malware_samples}")
        lines.append("")

    # SSL
    s = result.ssl
    lines.append("<b>SSL / crt.sh</b>")
    if s is None:
        lines.append("  Не удалось получить данные сертификатов.")
    else:
        lines.append(f"  first_seen: {esc(s.first_seen or '-')}")
        lines.append(f"  last_seen: {esc(s.last_seen or '-')}")
        lines.append(f"  Выдающие центры: {esc(', '.join(s.issuers) or '-')}")
        lines.append(f"  SAN-домены: {esc(', '.join(s.san_domains) or '-')}")
    lines.append("")

    # HTTP
    h = result.http
    lines.append("<b>HTTP / robots.txt</b>")
    if h is None:
        lines.append("  Сайт не ответил по HTTP/HTTPS.")
    else:
        lines.append(f"  Проверенный URL: {esc(h.url_checked or '-')}")
        lines.append(f"  Server: {esc(h.server or '-')}")
        lines.append(f"  Via: {esc(h.via or '-')}")
        lines.append(f"  X-Powered-By: {esc(h.x_powered_by or '-')}")
        lines.append(f"  cf-ray: {esc(h.cf_ray or '-')}")
        lines.append(f"  cf-cache-status: {esc(h.cf_cache_status or '-')}")
        lines.append(f"  robots.txt: {'есть' if h.robots_exists else 'нет'}")
        if h.robots_exists:
            lines.append(f"  Disallow: / : {'да' if h.robots_disallow_all else 'нет'}")
            lines.append(f"  Sitemap: {'найден' if h.robots_has_sitemap else 'нет'}")
            lines.append(f"  Минимальные Allow: {'да' if h.robots_has_minimal_allow else 'нет'}")
    lines.append("")

    # Flags with weights (explainability)
    lines.append("<b>Флаги риска (детализация)</b>")
    if not result.flags:
        lines.append("  Подозрительных признаков не выявлено.")
    else:
        total_weight = 0
        for f in result.flags:
            weight = f.weight
            total_weight += weight
            sign = "+" if weight >= 0 else ""
            lines.append(f"  {_flag_emoji(f.level)} ({sign}{weight}) {esc(f.code)}: {esc(f.message)}")

        lines.append("")
        lines.append(f"<b>Суммарный вес флагов:</b> {total_weight}")
        lines.append(f"<b>Итоговый score:</b> {score_view}/10")
        lines.append("📝 Веса: положительные увеличивают риск, отрицательные (trust signals) снижают.")

    return "\n".join(lines)
