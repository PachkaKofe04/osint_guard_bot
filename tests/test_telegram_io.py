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
