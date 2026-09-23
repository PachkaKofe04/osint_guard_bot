# config.py
import logging
from typing import FrozenSet, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Настройки из .env.

    Обязателен только BOT_TOKEN. Остальные ключи опциональны: без них
    соответствующая проверка деградирует, но бот работает. Что именно
    отваливается без ключа - видно в разделе меню «Статус источников».
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    BOT_TOKEN: str

    # Один ключ на URLhaus, ThreatFox и MalwareBazaar. Бесплатно: auth.abuse.ch
    ABUSECH_API_KEY: Optional[str] = None
    # Репутация IP, 1000 проверок в сутки бесплатно: abuseipdb.com
    ABUSEIPDB_API_KEY: Optional[str] = None
    # Резерв к Blockscout, один ключ на 60+ EVM-сетей: etherscan.io/apis
    ETHERSCAN_API_KEY: Optional[str] = None
    # Фишинг и вредонос от Google, бесплатно через Google Cloud Console
    SAFEBROWSING_API_KEY: Optional[str] = None
    # 70+ антивирусов. 500 запросов в сутки, коммерческое использование запрещено
    VIRUSTOTAL_API_KEY: Optional[str] = None
    # Репутация доменов и IP
    OTX_API_KEY: Optional[str] = None
    # Уточнение оператора телефона сверх офлайн-базы phonenumbers
    VERIPHONE_API_KEY: Optional[str] = None
    # Утечки. Платный; при пустом значении используется бесплатный XposedOrNot
    HIBP_API_KEY: Optional[str] = None

    # Хранится строкой намеренно. Для полей-списков pydantic-settings требует
    # строгий JSON и разбирает значение на уровне источника, до валидаторов:
    # ADMIN_IDS=123,456 и даже пустое ADMIN_IDS= роняли бота на старте.
    # Разбираем сами в admin_ids.
    ADMIN_IDS: str = ""

    @property
    def admin_ids(self) -> FrozenSet[int]:
        """
        Telegram id администраторов. Принимает любой разумный формат:
        пусто, 123, «123,456», «123; 456», «[123, 456]».

        Нечисловые фрагменты игнорируются: опечатка в .env не должна
        мешать боту запуститься.
        """
        text = self.ADMIN_IDS.strip().strip("[]").replace(";", ",")
        if not text:
            return frozenset()

        ids = set()
        for part in text.split(","):
            part = part.strip().strip("'\"")
            if not part:
                continue
            try:
                ids.add(int(part))
            except ValueError:
                log.warning("[config] ADMIN_IDS: пропускаю нечисловое значение %r", part)
        return frozenset(ids)


settings = Settings()
