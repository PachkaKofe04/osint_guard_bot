# tests/test_email_scanner.py
"""Тесты для Email сканера."""
import pytest
from email_scanner.scanner import validate_email_format, parse_email
from email_scanner.disposable import is_disposable_email, is_free_provider, get_provider_name
from email_scanner.risk_engine import calculate_email_risk
from email_scanner.models import EmailInfo
from utils.risk_types import RiskLevel


class TestValidateEmailFormat:
    """Тесты функции validate_email_format."""

    def test_valid_simple_email(self):
        """Простой валидный email."""
        assert validate_email_format("user@example.com") is True

    def test_valid_with_dots(self):
        """Email с точками в local part."""
        assert validate_email_format("user.name@example.com") is True

    def test_valid_with_plus(self):
        """Email с плюсом."""
        assert validate_email_format("user+tag@gmail.com") is True

    def test_valid_with_numbers(self):
        """Email с цифрами."""
        assert validate_email_format("user123@example.com") is True

    def test_valid_subdomain(self):
        """Email с поддоменом."""
        assert validate_email_format("user@mail.example.com") is True

    def test_invalid_no_at(self):
        """Email без @."""
        assert validate_email_format("userexample.com") is False

    def test_invalid_no_domain(self):
        """Email без домена."""
        assert validate_email_format("user@") is False

    def test_invalid_no_tld(self):
        """Email без TLD."""
        assert validate_email_format("user@example") is False

    def test_invalid_spaces(self):
        """Email с пробелами."""
        assert validate_email_format("user @example.com") is False

    def test_invalid_double_at(self):
        """Email с двумя @."""
        assert validate_email_format("user@@example.com") is False

    def test_invalid_short_tld(self):
        """Email со слишком коротким TLD."""
        assert validate_email_format("user@example.c") is False


class TestParseEmail:
    """Тесты функции parse_email."""

    def test_simple_email(self):
        """Простой email."""
        local, domain = parse_email("user@example.com")
        assert local == "user"
        assert domain == "example.com"

    def test_email_with_dots(self):
        """Email с точками."""
        local, domain = parse_email("user.name@example.com")
        assert local == "user.name"
        assert domain == "example.com"

    def test_no_at_symbol(self):
        """Email без @."""
        local, domain = parse_email("invalid")
        assert local == ""
        assert domain == ""

    def test_multiple_at(self):
        """Email с несколькими @."""
        local, domain = parse_email("user@host@example.com")
        assert local == "user@host"
        assert domain == "example.com"


class TestIsDisposableEmail:
    """Тесты функции is_disposable_email."""

    def test_tempmail(self):
        """Одноразовый домен tempmail."""
        assert is_disposable_email("tempmail.com") is True

    def test_guerrillamail(self):
        """Одноразовый домен guerrillamail."""
        assert is_disposable_email("guerrillamail.com") is True

    def test_mailinator(self):
        """Одноразовый домен mailinator."""
        assert is_disposable_email("mailinator.com") is True

    def test_yopmail(self):
        """Одноразовый домен yopmail."""
        assert is_disposable_email("yopmail.com") is True

    def test_10minutemail(self):
        """Одноразовый домен 10minutemail."""
        assert is_disposable_email("10minutemail.com") is True

    def test_gmail_not_disposable(self):
        """Gmail не одноразовый."""
        assert is_disposable_email("gmail.com") is False

    def test_regular_domain(self):
        """Обычный домен не одноразовый."""
        assert is_disposable_email("mycompany.com") is False

    def test_case_insensitive(self):
        """Регистр не важен."""
        assert is_disposable_email("TEMPMAIL.COM") is True
        assert is_disposable_email("TempMail.Com") is True


class TestIsFreeProvider:
    """Тесты функции is_free_provider."""

    def test_gmail(self):
        """Gmail — бесплатный провайдер."""
        assert is_free_provider("gmail.com") is True

    def test_yahoo(self):
        """Yahoo — бесплатный провайдер."""
        assert is_free_provider("yahoo.com") is True

    def test_outlook(self):
        """Outlook — бесплатный провайдер."""
        assert is_free_provider("outlook.com") is True

    def test_mail_ru(self):
        """Mail.ru — бесплатный провайдер."""
        assert is_free_provider("mail.ru") is True

    def test_yandex(self):
        """Яндекс — бесплатный провайдер."""
        assert is_free_provider("yandex.ru") is True

    def test_protonmail(self):
        """ProtonMail — бесплатный провайдер."""
        assert is_free_provider("protonmail.com") is True

    def test_corporate_not_free(self):
        """Корпоративный домен не бесплатный."""
        assert is_free_provider("company.com") is False

    def test_disposable_not_free(self):
        """Одноразовый email не в списке бесплатных."""
        assert is_free_provider("tempmail.com") is False


class TestGetProviderName:
    """Тесты функции get_provider_name."""

    def test_gmail(self):
        """Gmail имя провайдера."""
        assert get_provider_name("gmail.com") == "Google Gmail"

    def test_yahoo(self):
        """Yahoo имя провайдера."""
        assert get_provider_name("yahoo.com") == "Yahoo Mail"

    def test_outlook(self):
        """Outlook имя провайдера."""
        assert get_provider_name("outlook.com") == "Microsoft Outlook"

    def test_mail_ru(self):
        """Mail.ru имя провайдера."""
        assert get_provider_name("mail.ru") == "Mail.ru"

    def test_yandex(self):
        """Яндекс имя провайдера."""
        assert get_provider_name("yandex.ru") == "Яндекс Почта"

    def test_protonmail(self):
        """ProtonMail имя провайдера."""
        assert get_provider_name("protonmail.com") == "ProtonMail"

    def test_disposable_provider(self):
        """Одноразовый email провайдер."""
        assert get_provider_name("tempmail.com") == "Одноразовый email"

    def test_unknown_domain(self):
        """Неизвестный домен."""
        assert get_provider_name("unknown.com") == ""


class TestCalculateEmailRisk:
    """Тесты функции calculate_email_risk."""

    def test_none_info(self):
        """Если info=None — средний риск."""
        level, flags, score = calculate_email_risk(None)
        assert any(f.code == "EMAIL_ANALYSIS_FAILED" for f in flags)

    def test_invalid_format_high_risk(self):
        """Невалидный формат — высокий риск."""
        info = EmailInfo(
            email="invalid",
            local_part="",
            domain="",
            is_valid_format=False,
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "INVALID_FORMAT" for f in flags)
        assert score >= 5

    def test_disposable_high_risk(self):
        """Одноразовый email — высокий риск."""
        info = EmailInfo(
            email="test@tempmail.com",
            local_part="test",
            domain="tempmail.com",
            is_disposable=True,
            has_mx_records=True,
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "DISPOSABLE_EMAIL" for f in flags)
        # DISPOSABLE_EMAIL=4, NO_BREACHES=-1 = 3
        assert score >= 3

    def test_no_mx_records_risk(self):
        """Нет MX записей — риск."""
        info = EmailInfo(
            email="test@nonexistent.com",
            local_part="test",
            domain="nonexistent.com",
            has_mx_records=False,
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "NO_MX_RECORDS" for f in flags)

    def test_many_breaches_high_risk(self):
        """Много утечек — высокий риск."""
        info = EmailInfo(
            email="test@example.com",
            local_part="test",
            domain="example.com",
            has_mx_records=True,
            breach_count=10,
            breaches=["breach1", "breach2", "breach3", "breach4"],
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "MANY_BREACHES" for f in flags)

    def test_few_breaches_medium_risk(self):
        """Несколько утечек — средний риск."""
        info = EmailInfo(
            email="test@example.com",
            local_part="test",
            domain="example.com",
            has_mx_records=True,
            breach_count=3,
            breaches=["breach1", "breach2", "breach3"],
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "FEW_BREACHES" for f in flags)

    def test_no_breaches_trust(self):
        """Нет утечек — доверие."""
        info = EmailInfo(
            email="test@example.com",
            local_part="test",
            domain="example.com",
            has_mx_records=True,
            breach_count=0,
            breaches=[],
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "NO_BREACHES" for f in flags)

    def test_free_provider_low_risk(self):
        """Бесплатный провайдер — низкий риск."""
        info = EmailInfo(
            email="test@gmail.com",
            local_part="test",
            domain="gmail.com",
            is_free_provider=True,
            has_mx_records=True,
            provider_name="Google Gmail",
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "FREE_PROVIDER" for f in flags)

    def test_corporate_email_trust(self):
        """Корпоративный email — доверие."""
        info = EmailInfo(
            email="employee@company.com",
            local_part="employee",
            domain="company.com",
            is_corporate=True,
            has_mx_records=True,
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "CORPORATE_EMAIL" for f in flags)

    def test_known_provider_trust(self):
        """Известный провайдер — доверие."""
        info = EmailInfo(
            email="test@gmail.com",
            local_part="test",
            domain="gmail.com",
            has_mx_records=True,
            provider_name="Google Gmail",
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "KNOWN_PROVIDER" for f in flags)

    def test_new_domain_risk(self):
        """Новый домен — риск."""
        info = EmailInfo(
            email="test@newdomain.com",
            local_part="test",
            domain="newdomain.com",
            has_mx_records=True,
            domain_age_days=15,
        )
        level, flags, score = calculate_email_risk(info)
        assert any(f.code == "NEW_DOMAIN" for f in flags)

    def test_clean_corporate_email(self):
        """Чистый корпоративный email — низкий риск."""
        info = EmailInfo(
            email="john.doe@microsoft.com",
            local_part="john.doe",
            domain="microsoft.com",
            is_valid_format=True,
            has_mx_records=True,
            is_disposable=False,
            is_free_provider=False,
            is_corporate=True,
            breach_count=0,
        )
        level, flags, score = calculate_email_risk(info)
        assert level == RiskLevel.LOW
        assert score <= 3
