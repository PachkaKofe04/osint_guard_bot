# wallet_scanner/formatter.py
"""Форматирование результатов сканирования Wallet для Telegram."""
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
    lines.append(f"<code>{result.address}</code>")
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
            lines.append(f"💱 <b>Криптовалюта:</b> {info.currency}")
            lines.append("")

            # Предупреждение о скаме
            if info.is_scam:
                lines.append("🚨 <b>ВНИМАНИЕ: СКАМ-АДРЕС!</b>")
                if info.scam_labels:
                    lines.append(f"    Метки: {', '.join(info.scam_labels)}")
                lines.append("    ⚠️ НЕ отправляйте средства на этот адрес!")
                lines.append("")

            # Известная биржа/сервис
            if info.exchange_name:
                lines.append(f"🏛️ <b>Известный адрес:</b> {info.exchange_name}")
                lines.append("")

            # Баланс
            if info.balance is not None:
                if info.currency == "BTC":
                    balance_str = f"{info.balance:.8f} BTC"
                elif info.currency == "ETH":
                    balance_str = f"{info.balance:.6f} ETH"
                else:
                    balance_str = f"{info.balance} {info.currency}"

                lines.append(f"💰 <b>Баланс:</b> {balance_str}")

                if info.balance_usd:
                    lines.append(f"    ≈ ${info.balance_usd:,.2f} USD")
                lines.append("")

            # Транзакции
            if info.tx_count is not None:
                lines.append(f"📊 <b>Транзакций:</b> {info.tx_count}")
                lines.append("")

            # Смарт-контракт
            if info.is_contract:
                lines.append("📜 <b>Тип:</b> Смарт-контракт")
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
            lines.append(f"    {flag_emoji} {flag.message}")

    # Ссылки на блокчейн-эксплореры
    if info and info.is_valid:
        lines.append("")
        lines.append("🔗 <b>Просмотреть:</b>")
        if info.currency == "BTC":
            lines.append(f"    <a href=\"https://blockchain.info/address/{result.address}\">Blockchain.info</a>")
        elif info.currency == "ETH":
            lines.append(f"    <a href=\"https://etherscan.io/address/{result.address}\">Etherscan</a>")
        elif info.currency == "TRX":
            lines.append(f"    <a href=\"https://tronscan.org/#/address/{result.address}\">TronScan</a>")
        elif info.currency == "LTC":
            lines.append(f"    <a href=\"https://blockchair.com/litecoin/address/{result.address}\">Blockchair</a>")

    return "\n".join(lines)
