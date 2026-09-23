# wallet_scanner/formatter.py
"""Форматирование результатов сканирования Wallet для Telegram."""
from utils.safe_html import esc
from wallet_scanner.models import WalletScanResult
from utils.risk_types import get_risk_emoji, get_risk_label, RiskLevel


# Эмодзи для криптовалют
CURRENCY_EMOJI = {
    "BTC": "₿",
    "ETH": "Ξ",
    "LTC": "Ł",
    "TRX": "🔺",
    "XRP": "✕",
    "DOGE": "🐕",
    "SOL": "◎",
    "XMR": "ɱ",
}


def format_wallet_result(result: WalletScanResult) -> str:
    """
    Форматирует результат сканирования кошелька для отправки в Telegram.

    Args:
        result: Результат сканирования

    Returns:
        Отформатированная строка с HTML разметкой
    """
    info = result.info
    emoji = get_risk_emoji(result.score)
    level_label = get_risk_label(result.risk_level)
    currency_emoji = CURRENCY_EMOJI.get(result.currency, "💰")

    lines = []
    lines.append(f"{currency_emoji} <b>Анализ криптокошелька</b>")
    lines.append(f"<code>{esc(result.address)}</code>")
    lines.append("")

    # Риск
    lines.append(f"{emoji} <b>{level_label}</b> (оценка: {result.score}/10)")
    lines.append("")

    if info:
        if not info.is_valid:
            lines.append("❌ <b>Невалидный адрес</b>")
            lines.append("Формат адреса не распознан")
            lines.append("")
        else:
            # Криптовалюта
            lines.append(f"💱 <b>Криптовалюта:</b> {esc(info.currency)}")
            lines.append("")

            # Скам-проверка. Три исхода, и их нельзя путать:
            # найден в базе / база доступна и адреса в ней нет / базы нет.
            if info.is_scam:
                lines.append("🚨 <b>ВНИМАНИЕ: СКАМ-АДРЕС!</b>")
                if info.scam_labels:
                    lines.append(f"    Метки: {esc(', '.join(info.scam_labels))}")
                lines.append("    ⚠️ НЕ отправляйте средства на этот адрес!")
                lines.append("")
            elif info.scam_check_performed:
                lines.append("✅ <b>Скам-базы:</b> адрес не числится")
                lines.append("")
            else:
                lines.append("⚠️ <b>Скам-проверка не выполнена</b>")
                lines.append("    База скам-адресов сейчас недоступна.")
                lines.append("    Отсутствие предупреждения не значит, что адрес чист.")
                lines.append("")

            # Известная биржа/сервис
            if info.exchange_name:
                lines.append(f"🏛️ <b>Известный адрес:</b> {esc(info.exchange_name)}")
                lines.append("")

            # Баланс
            if info.balance is not None:
                if info.currency == "BTC":
                    balance_str = f"{info.balance:.8f} BTC"
                elif info.currency == "ETH":
                    balance_str = f"{info.balance:.6f} ETH"
                else:
                    balance_str = f"{info.balance} {esc(info.currency)}"

                lines.append(f"💰 <b>Баланс:</b> {esc(balance_str)}")

                if info.balance_usd:
                    lines.append(f"    ≈ ${info.balance_usd:,.2f} USD")
                if info.data_source:
                    lines.append(f"    <i>источник: {esc(info.data_source)}</i>")
                lines.append("")
            elif not info.balance_available:
                # Не сбой, а свойство сети: Monero не раскрывает балансы
                lines.append(
                    f"🔒 <b>Баланс недоступен:</b> сеть {esc(info.currency)} "
                    f"не раскрывает балансы по адресу"
                )
                lines.append("")
            else:
                lines.append("⚠️ <b>Баланс получить не удалось</b>")
                lines.append("    Источник данных не ответил, попробуй позже.")
                lines.append("")

            # Транзакции + активность
            if info.tx_count is not None:
                lines.append(f"📊 <b>Транзакций:</b> {info.tx_count}")
            if info.first_seen:
                lines.append(f"📅 <b>Первая активность:</b> {info.first_seen.strftime('%Y-%m-%d')}")
            if info.last_seen:
                lines.append(f"🕒 <b>Последняя активность:</b> {info.last_seen.strftime('%Y-%m-%d')}")
            if info.tx_count is not None or info.first_seen or info.last_seen:
                lines.append("")

            # Тип адреса
            if info.is_contract:
                name = f" ({esc(info.contract_name)})" if info.contract_name else ""
                lines.append(f"📜 <b>Тип:</b> Смарт-контракт{name}")
                lines.append("")
            elif info.is_smart_account:
                lines.append("📜 <b>Тип:</b> Кошелёк со смарт-аккаунтом (EIP-7702)")
                lines.append("")

    # Флаги рисков
    if result.flags:
        lines.append("📋 <b>Детали анализа:</b>")
        for flag in result.flags:
            if flag.level == RiskLevel.HIGH:
                flag_emoji = "🔴"
            elif flag.level == RiskLevel.MEDIUM:
                flag_emoji = "🟡"
            else:
                flag_emoji = "🟢"
            lines.append(f"    {flag_emoji} {esc(flag.message)}")

    # Ссылки на блокчейн-эксплореры
    EXPLORER_URLS = {
        "BTC":  f"https://blockchair.com/bitcoin/address/{esc(result.address)}",
        "ETH":  f"https://etherscan.io/address/{esc(result.address)}",
        "LTC":  f"https://blockchair.com/litecoin/address/{esc(result.address)}",
        "DOGE": f"https://blockchair.com/dogecoin/address/{esc(result.address)}",
        "TRX":  f"https://tronscan.org/#/address/{esc(result.address)}",
        "XRP":  f"https://xrpscan.com/account/{esc(result.address)}",
        "SOL":  f"https://solscan.io/account/{esc(result.address)}",
        "XMR":  f"https://xmrchain.net/search?value={esc(result.address)}",
    }
    if info and info.is_valid and result.currency in EXPLORER_URLS:
        lines.append("")
        lines.append(f"🔗 <a href=\"{EXPLORER_URLS[result.currency]}\">Открыть в эксплорере</a>")

    return "\n".join(lines)
