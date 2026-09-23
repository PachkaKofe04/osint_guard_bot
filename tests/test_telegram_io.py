# tests/test_telegram_io.py
"""Тесты безопасной отправки сообщений в Telegram."""
from utils.telegram_io import SAFE_CHUNK_LEN, TELEGRAM_MAX_LEN, split_text


class TestSplitText:
    def test_short_text_not_split(self):
        assert split_text("короткий текст") == ["короткий текст"]

    def test_empty_text(self):
        assert split_text("") == [""]

    def test_long_text_is_split(self):
        text = "\n".join(f"строка номер {i}" for i in range(1000))
        chunks = split_text(text)
        assert len(chunks) > 1

    def test_every_chunk_fits_telegram_limit(self):
        text = "\n".join(f"строка номер {i}" for i in range(2000))
        for chunk in split_text(text):
            assert len(chunk) <= SAFE_CHUNK_LEN
            assert len(chunk) < TELEGRAM_MAX_LEN

    def test_splits_on_line_boundaries(self):
        """Строки не должны рваться посередине, если влезают целиком."""
        text = "\n".join("x" * 100 for _ in range(200))
        for chunk in split_text(text):
            for line in chunk.split("\n"):
                assert line == "x" * 100

    def test_no_content_lost(self):
        text = "\n".join(f"data-{i}" for i in range(500))
        assert "\n".join(split_text(text)) == text

    def test_single_huge_line_is_hard_split(self):
        """Одна гигантская строка (например, robots.txt) всё равно должна пройти."""
        text = "y" * 20000
        chunks = split_text(text)
        assert len(chunks) > 1
        assert all(len(c) <= SAFE_CHUNK_LEN for c in chunks)
        assert "".join(chunks) == text

    def test_domain_report_scenario(self):
        """Отчёт по домену с большим SAN-списком доходил до 8546 символов."""
        report = "🔍 <b>Отчёт</b>\n" + "\n".join(
            f"sub{i}.example.com" for i in range(500)
        )
        assert len(report) > TELEGRAM_MAX_LEN
        chunks = split_text(report)
        assert all(len(c) <= SAFE_CHUNK_LEN for c in chunks)


class TestLongLineSplitting:
    """
    Длинная строка должна рваться по разделителям, а не посреди слова.

    В отчёте по google.com список из 518 SAN-доменов разошёлся по сообщениям
    как «*.m» в конце одного и «etric.gstatic.com» в начале следующего.
    """

    @staticmethod
    def _san_line(count=400):
        return ", ".join(f"*.subdomain{i}.example.com" for i in range(count))

    def test_every_part_ends_on_whole_token(self):
        for part in split_text(self._san_line()):
            assert part.rstrip().rstrip(",").endswith(".com"), part[-40:]

    def test_nothing_is_lost(self):
        line = self._san_line()
        assert "".join(split_text(line)).replace(" ", "") == line.replace(" ", "")

    def test_line_without_separators_still_splits(self):
        """Строка без пробелов и запятых всё равно должна пролезть."""
        huge = "x" * 9000
        parts = split_text(huge)
        assert len(parts) > 1
        assert "".join(parts) == huge

    def test_semicolon_separated_line(self):
        line = "; ".join(f"item{i}" for i in range(2000))
        for part in split_text(line):
            assert not part.rstrip().endswith("ite"), "разрез посреди слова"


class TestReportPreviewLimits:
    """Отчёт не должен вываливать сотни записей: их никто не читает."""

    def test_san_list_is_capped(self):
        from datetime import datetime, timezone

        from domain_scanner.formatter import SAN_PREVIEW_LIMIT, format_details
        from domain_scanner.models import DomainScanResult, SslInfo
        from utils.risk_types import RiskLevel

        result = DomainScanResult(
            domain="x.com", normalized_domain="x.com",
            risk_level=RiskLevel.LOW, flags=[], score=0,
            ssl=SslInfo(san_domains=[f"s{i}.x.com" for i in range(518)]),
            scanned_at=datetime.now(timezone.utc),
        )
        text = format_details(result)

        assert "518" in text, "общее число должно быть видно"
        assert f"и ещё {518 - SAN_PREVIEW_LIMIT}" in text
        assert "s500.x.com" not in text, "полный список выводиться не должен"
