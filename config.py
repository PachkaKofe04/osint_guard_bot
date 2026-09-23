# config.py
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    BOT_TOKEN: str
    VERIPHONE_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    ADMIN_IDS: List[int] = Field(default_factory=list)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
