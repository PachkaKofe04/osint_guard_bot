# scan_registry.py
"""
Реестр направлений проверки.

Единственный источник правды о том, что умеет бот. Из него строятся:
  - меню и подменю (keyboards/menu_kb.py);
  - универсальный сценарий "кнопка -> ввод -> карточка" (handlers/scan_flow.py);
  - экран статуса источников данных.

Добавление нового сканера = одна запись здесь. Меню подхватит автоматически,
рассинхрон меню и реальных возможностей становится невозможен.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from config import settings

# --- сканеры ---
from bin_scanner.scanner import scan_bin_async
from domain_scanner.scanner import scan_domain
from email_scanner.scanner import scan_email
from exif_scanner.scanner import scan_exif
from ip_scanner.scanner import scan_ip
from leak_scanner.scanner import scan_leaks
from phone_scanner.scanner import scan_phone
from qr_scanner.scanner import scan_qr
from url_scanner.scanner import scan_url
from username_scanner.scanner import scan_username
from wallet_scanner.scanner import scan_wallet

# --- форматтеры ---
from bin_scanner.formatter import format_bin_summary
from domain_scanner.formatter import format_summary as format_domain_summary
from email_scanner.formatter import format_email_result
from exif_scanner.formatter import format_exif_result
from ip_scanner.formatter import format_ip_result
from leak_scanner.formatter import format_leak_result
from phone_scanner.formatter import format_phone_summary
from qr_scanner.formatter import format_qr_result
from url_scanner.formatter import format_url_result
from username_scanner.formatter import format_username_result
from wallet_scanner.formatter import format_wallet_result


# Ввод, которого ждём от пользователя после нажатия кнопки
INPUT_TEXT = "text"
INPUT_IMAGE = "image"

# Состояние направления
STATUS_OK = "ok"
STATUS_LIMITED = "limited"


@dataclass(frozen=True)
class Direction:
    """Одно направление проверки."""

    key: str
    icon: str
    title: str
    category: str
    prompt: str                       # что прислать после нажатия кнопки
    waiting: str                      # текст на время скана
    scan: Callable[..., Awaitable]    # корутина скана
    format: Callable[[object], str]   # форматтер результата
    input_kind: str = INPUT_TEXT
    # Какие типы ввода направление принимает (см. utils/input_detect).
    # Пустой кортеж означает «проверять не нужно».
    # Без этого в сканер проходил любой мусор: одиночный «+» доходил до
    # телефонного сканера и получал осмысленную оценку 6/10.
    accepts: Tuple[str, ...] = ()
    # Как назвать ожидаемые данные в сообщении об ошибке
    expects: str = ""
    examples: Tuple[str, ...] = ()
    monitorable: bool = False
    status: str = STATUS_OK
    status_note: str = ""
    commands: Tuple[str, ...] = ()    # алиасы-команды, для экрана помощи

    @property
    def button(self) -> str:
        mark = " ⚠️" if self.status == STATUS_LIMITED else ""
        return f"{self.icon} {self.title}{mark}"

    @property
    def label(self) -> str:
        return f"{self.icon} {self.title}"


@dataclass(frozen=True)
class Category:
    """Раздел главного меню."""

    key: str
    icon: str
    title: str
    direction_keys: Tuple[str, ...]

    @property
    def button(self) -> str:
        return f"{self.icon} {self.title}"


async def _scan_leaks_with_key(query: str):
    """scan_leaks принимает ключ отдельным аргументом, приводим к общей сигнатуре."""
    return await scan_leaks(query, api_key=settings.HIBP_API_KEY)


DIRECTIONS: Dict[str, Direction] = {
    d.key: d
    for d in (
        Direction(
            key="domain",
            accepts=("domain", "url"),
            expects="адрес сайта",
            icon="🌍",
            title="Домен",
            category="web",
            prompt=(
                "Пришли адрес сайта - проверю возраст домена, владельца, DNS, "
                "SSL-сертификат и признаки фишинга."
            ),
            waiting="⏳ Сканирую домен, это может занять несколько секунд...",
            scan=scan_domain,
            format=format_domain_summary,
            examples=("example.com", "baodex.cc"),
            monitorable=True,
            commands=("/scan", "/domain"),
        ),
        Direction(
            key="url",
            accepts=("url", "domain"),
            expects="ссылку",
            icon="🔗",
            title="Ссылка",
            category="web",
            prompt=(
                "Пришли ссылку - разверну сокращённую, покажу цепочку редиректов "
                "и проверю на фишинг."
            ),
            waiting="🔍 Проверяю ссылку...",
            scan=scan_url,
            format=format_url_result,
            examples=("https://bit.ly/abc123", "https://example.com/page"),
            commands=("/url",),
        ),
        Direction(
            key="email",
            accepts=("email",),
            expects="email-адрес",
            icon="📧",
            title="Email",
            category="personal",
            prompt=(
                "Пришли email - проверю формат, MX-записи, одноразовость "
                "и возраст домена.\n\n"
                "Поиск по сервисам, где засветился адрес, запускается "
                "отдельной кнопкой: он идёт дольше."
            ),
            waiting="📧 Проверяю email...",
            scan=scan_email,
            format=format_email_result,
            examples=("user@example.com",),
            monitorable=True,
            commands=("/email",),
        ),
        Direction(
            key="phone",
            accepts=("phone",),
            expects="номер телефона",
            icon="📞",
            title="Телефон",
            category="personal",
            prompt="Пришли номер - определю страну, оператора, тип линии и регион.",
            waiting="📞 Проверяю номер...",
            scan=scan_phone,
            format=format_phone_summary,
            examples=("+79991234567", "8 999 123 45 67"),
            commands=("/phone",),
        ),
        Direction(
            key="username",
            accepts=("username", "ambiguous"),
            expects="никнейм",
            icon="👤",
            title="Никнейм",
            category="personal",
            prompt=(
                "Пришли никнейм - поищу его на 20 платформах. "
                "Потом можно будет запустить углублённый поиск по ~500 сайтам."
            ),
            waiting="👤 Ищу никнейм на платформах, до 30 секунд...",
            scan=scan_username,
            format=format_username_result,
            examples=("johndoe", "@telegram_user"),
            commands=("/username", "/user"),
        ),
        Direction(
            key="leak",
            accepts=("email",),
            expects="email-адрес",
            icon="🔓",
            title="Утечки",
            category="personal",
            prompt=(
                "Пришли email - проверю его по базам известных утечек: "
                "где засветился, что украли и когда."
            ),
            waiting="🔓 Проверяю по базам утечек...",
            scan=_scan_leaks_with_key,
            format=format_leak_result,
            examples=("user@example.com",),
            commands=("/leak",),
        ),
        Direction(
            key="bin",
            accepts=("bin",),
            expects="6-8 цифр номера карты",
            icon="💳",
            title="Карта (BIN)",
            category="finance",
            prompt=(
                "Пришли первые 6-8 цифр карты - покажу платёжную систему, "
                "банк-эмитент, страну и тип карты.\n\n"
                "Полный номер карты присылать не нужно и небезопасно."
            ),
            waiting="💳 Проверяю BIN...",
            scan=scan_bin_async,
            format=format_bin_summary,
            examples=("427229", "45717360"),
            commands=("/bin",),
        ),
        Direction(
            key="wallet",
            accepts=("wallet",),
            expects="адрес криптокошелька",
            icon="💰",
            title="Криптокошелёк",
            category="finance",
            prompt=(
                "Пришли адрес кошелька - покажу баланс, активность и проверю "
                "по базе скам-адресов.\n\n"
                "Баланс доступен для BTC, ETH, LTC, DOGE, TRX, XRP, SOL.\n"
                "Для Monero баланс не раскрывается самой сетью."
            ),
            waiting="💰 Проверяю кошелёк...",
            scan=scan_wallet,
            format=format_wallet_result,
            examples=("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",),
            commands=("/wallet",),
        ),
        Direction(
            key="ip",
            accepts=("ip",),
            expects="IP-адрес",
            icon="🌐",
            title="IP-адрес",
            category="network",
            prompt=(
                "Пришли IP - покажу геолокацию, провайдера, ASN "
                "и признаки VPN, прокси или хостинга."
            ),
            waiting="🌐 Проверяю IP-адрес...",
            scan=scan_ip,
            format=format_ip_result,
            examples=("8.8.8.8", "2001:4860:4860::8888"),
            monitorable=True,
            commands=("/ip",),
        ),
        Direction(
            key="exif",
            icon="🖼",
            title="EXIF фотографии",
            category="files",
            prompt=(
                "Пришли изображение <b>файлом</b> - достану GPS-координаты, "
                "модель камеры, дату съёмки и остальные метаданные.\n\n"
                "⚠️ Именно файлом, не фото: при обычной отправке Telegram сжимает "
                "картинку и вырезает все метаданные.\n"
                "• Телефон: скрепка -> Файл\n"
                "• ПК: перетащи с зажатым Shift или выбери «Отправить без сжатия»"
            ),
            waiting="🖼 Читаю метаданные изображения...",
            scan=scan_exif,
            format=format_exif_result,
            input_kind=INPUT_IMAGE,
        ),
        Direction(
            key="qr",
            icon="📱",
            title="QR-код",
            category="files",
            prompt=(
                "Пришли изображение с QR-кодом - распознаю содержимое и проверю его: "
                "ссылку на фишинг, WiFi-пароль, криптоадрес, контакт или текст.\n\n"
                "Лучше отправлять файлом без сжатия - так распознавание точнее."
            ),
            waiting="📱 Распознаю QR-код...",
            scan=scan_qr,
            format=format_qr_result,
            input_kind=INPUT_IMAGE,
            commands=("/qr",),
        ),
    )
}


CATEGORIES: Tuple[Category, ...] = (
    Category("web", "🌐", "Сайты и ссылки", ("domain", "url")),
    Category("personal", "👤", "Личные данные", ("email", "phone", "username", "leak")),
    Category("finance", "💳", "Финансы", ("bin", "wallet")),
    Category("files", "🖼", "Файлы", ("exif", "qr")),
    Category("network", "📶", "Сеть", ("ip",)),
)


def get_direction(key: str) -> Optional[Direction]:
    return DIRECTIONS.get(key)


def get_category(key: str) -> Optional[Category]:
    for category in CATEGORIES:
        if category.key == key:
            return category
    return None


def directions_of(category: Category) -> List[Direction]:
    return [DIRECTIONS[k] for k in category.direction_keys if k in DIRECTIONS]


def monitorable_directions() -> List[Direction]:
    return [d for d in DIRECTIONS.values() if d.monitorable]


def limited_directions() -> List[Direction]:
    return [d for d in DIRECTIONS.values() if d.status == STATUS_LIMITED]
