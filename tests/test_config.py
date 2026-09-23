# tests/test_config.py
"""
Разбор настроек из .env.

Список администраторов раньше был полем типа List[int]. Для таких полей
pydantic-settings требует строгий JSON и разбирает значение на уровне
источника, до валидаторов, поэтому бот падал на старте и от ADMIN_IDS=123,456,
и от пустого ADMIN_IDS=. То есть обойти rate limit не мог никто: любая
попытка настроить админов убивала запуск.
"""
import os
import tempfile

import pytest

from config import Settings


def _settings(env_body: str) -> Settings:
    """Создаёт Settings из временного .env."""
    fd, path = tempfile.mkstemp(suffix=".env")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write("BOT_TOKEN=test-token\n" + env_body)
    try:
        return Settings(_env_file=path)
    finally:
        os.unlink(path)


class TestAdminIds:
    @pytest.mark.parametrize("body,expected", [
        ("", set()),
        ("ADMIN_IDS=\n", set()),
        ("ADMIN_IDS=   \n", set()),
        ("ADMIN_IDS=123\n", {123}),
        ("ADMIN_IDS=123,456\n", {123, 456}),
        ("ADMIN_IDS=123, 456 , 789\n", {123, 456, 789}),
        ("ADMIN_IDS=[123,456]\n", {123, 456}),
        ("ADMIN_IDS=123;456\n", {123, 456}),
        ("ADMIN_IDS=123,123,456\n", {123, 456}),
    ])
    def test_accepts_human_formats(self, body, expected):
        assert set(_settings(body).admin_ids) == expected

    def test_garbage_does_not_break_startup(self):
        """Опечатка в .env не должна мешать боту запуститься."""
        assert set(_settings("ADMIN_IDS=123,оп,456\n").admin_ids) == {123, 456}

    def test_returns_frozenset_for_fast_lookup(self):
        """Проверка user_id in admin_ids выполняется на каждом сообщении."""
        assert isinstance(_settings("ADMIN_IDS=1\n").admin_ids, frozenset)


class TestOptionalKeys:
    """Без ключей бот обязан подниматься: проверки деградируют, но работают."""

    @pytest.mark.parametrize("field", [
        "ABUSECH_API_KEY", "ABUSEIPDB_API_KEY", "ETHERSCAN_API_KEY",
        "SAFEBROWSING_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY",
        "VERIPHONE_API_KEY", "HIBP_API_KEY",
    ])
    def test_key_is_optional(self, field):
        assert getattr(_settings(""), field) is None

    def test_bot_token_is_required(self):
        fd, path = tempfile.mkstemp(suffix=".env")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write("ADMIN_IDS=1\n")
        try:
            # Переменная окружения процесса перебила бы .env, поэтому убираем её
            saved = os.environ.pop("BOT_TOKEN", None)
            with pytest.raises(Exception):
                Settings(_env_file=path)
        finally:
            if saved is not None:
                os.environ["BOT_TOKEN"] = saved
            os.unlink(path)

    def test_unknown_variable_is_ignored(self):
        """Лишняя переменная в .env не должна ронять запуск."""
        assert _settings("SOME_FUTURE_KEY=x\n").BOT_TOKEN == "test-token"
