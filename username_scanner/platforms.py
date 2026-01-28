# username_scanner/platforms.py
"""Конфигурация платформ для проверки username."""
from typing import Dict, List, NamedTuple, Optional


class Platform(NamedTuple):
    """Конфигурация платформы."""
    name: str
    url_template: str  # {username} будет заменён на никнейм
    error_type: str = "status_code"  # status_code или message
    error_codes: tuple = (404,)
    error_message: Optional[str] = None
    headers: dict = {}
    category: str = "social"


# Список платформ для проверки
PLATFORMS: List[Platform] = [
    # Социальные сети
    Platform(
        name="GitHub",
        url_template="https://github.com/{username}",
        error_codes=(404,),
        category="development",
    ),
    Platform(
        name="Twitter/X",
        url_template="https://twitter.com/{username}",
        error_codes=(404,),
        category="social",
    ),
    Platform(
        name="Instagram",
        url_template="https://www.instagram.com/{username}/",
        error_codes=(404,),
        category="social",
    ),
    Platform(
        name="Telegram",
        url_template="https://t.me/{username}",
        error_type="message",
        error_message="If you have <strong>Telegram</strong>, you can contact",
        category="messenger",
    ),
    Platform(
        name="VK",
        url_template="https://vk.com/{username}",
        error_type="message",
        error_message="Страница удалена",
        category="social",
    ),
    Platform(
        name="YouTube",
        url_template="https://www.youtube.com/@{username}",
        error_codes=(404,),
        category="video",
    ),
    Platform(
        name="TikTok",
        url_template="https://www.tiktok.com/@{username}",
        error_codes=(404,),
        category="video",
    ),
    Platform(
        name="Reddit",
        url_template="https://www.reddit.com/user/{username}",
        error_codes=(404,),
        category="social",
    ),
    Platform(
        name="LinkedIn",
        url_template="https://www.linkedin.com/in/{username}",
        error_codes=(404, 999),  # LinkedIn часто возвращает 999
        category="professional",
    ),
    Platform(
        name="Pinterest",
        url_template="https://www.pinterest.com/{username}/",
        error_codes=(404,),
        category="social",
    ),
    Platform(
        name="Medium",
        url_template="https://medium.com/@{username}",
        error_codes=(404,),
        category="blog",
    ),
    Platform(
        name="GitLab",
        url_template="https://gitlab.com/{username}",
        error_codes=(404,),
        category="development",
    ),
    Platform(
        name="Twitch",
        url_template="https://www.twitch.tv/{username}",
        error_codes=(404,),
        category="streaming",
    ),
    Platform(
        name="Steam",
        url_template="https://steamcommunity.com/id/{username}",
        error_type="message",
        error_message="The specified profile could not be found",
        category="gaming",
    ),
    Platform(
        name="Spotify",
        url_template="https://open.spotify.com/user/{username}",
        error_codes=(404,),
        category="music",
    ),
    Platform(
        name="SoundCloud",
        url_template="https://soundcloud.com/{username}",
        error_codes=(404,),
        category="music",
    ),
    Platform(
        name="Flickr",
        url_template="https://www.flickr.com/people/{username}/",
        error_codes=(404,),
        category="photo",
    ),
    Platform(
        name="Behance",
        url_template="https://www.behance.net/{username}",
        error_codes=(404,),
        category="design",
    ),
    Platform(
        name="Dribbble",
        url_template="https://dribbble.com/{username}",
        error_codes=(404,),
        category="design",
    ),
    Platform(
        name="HackerNews",
        url_template="https://news.ycombinator.com/user?id={username}",
        error_type="message",
        error_message="No such user",
        category="news",
    ),
]


# Подозрительные паттерны в никнеймах
SUSPICIOUS_PATTERNS = [
    "admin", "support", "help", "official",
    "security", "verify", "verified", "mod",
    "moderator", "staff", "team", "service",
    "customer", "billing", "account", "login",
]

# Шаблоны для фишинга (когда добавляют к известным брендам)
BRAND_PATTERNS = [
    "google", "facebook", "microsoft", "apple",
    "amazon", "paypal", "netflix", "instagram",
    "twitter", "telegram", "whatsapp", "binance",
    "coinbase", "tinkoff", "sberbank", "vk",
]


def get_platforms_by_category(category: str) -> List[Platform]:
    """Возвращает платформы по категории."""
    return [p for p in PLATFORMS if p.category == category]


def get_all_categories() -> List[str]:
    """Возвращает все категории платформ."""
    return list(set(p.category for p in PLATFORMS))
