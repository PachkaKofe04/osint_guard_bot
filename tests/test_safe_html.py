# tests/test_safe_html.py
"""Тесты экранирования пользовательских данных для parse_mode=HTML."""
from utils.safe_html import esc, esc_attr, strip_tags


class TestEsc:
    def test_escapes_angle_brackets(self):
        assert esc("<b>bold</b>") == "&lt;b&gt;bold&lt;/b&gt;"

    def test_escapes_ampersand(self):
        assert esc("Tom & Jerry") == "Tom &amp; Jerry"

    def test_ampersand_escaped_before_brackets(self):
        """&lt; не должен превратиться в &amp;lt; - порядок замен важен."""
        assert esc("<") == "&lt;"
        assert esc("&lt;") == "&amp;lt;"

    def test_none_becomes_empty_string(self):
        """None не должен печататься как 'None' в отчётах."""
        assert esc(None) == ""

    def test_non_string_converted(self):
        assert esc(42) == "42"
        assert esc(3.14) == "3.14"

    def test_plain_text_unchanged(self):
        assert esc("обычный текст 123") == "обычный текст 123"

    def test_quotes_not_escaped_in_text(self):
        """В тексте сообщения кавычки допустимы как есть."""
        assert esc('say "hi"') == 'say "hi"'

    def test_real_injection_payload(self):
        """Полезная нагрузка, ломавшая parse_mode=HTML."""
        assert esc('<b>evil</b> & "x"') == '&lt;b&gt;evil&lt;/b&gt; &amp; "x"'

    def test_script_tag_neutralised(self):
        assert "<script" not in esc("<script>alert(1)</script>")


class TestEscAttr:
    def test_escapes_quotes(self):
        assert esc_attr('a"b') == "a&quot;b"

    def test_escapes_brackets_too(self):
        assert esc_attr('<a href="x">') == "&lt;a href=&quot;x&quot;&gt;"


class TestStripTags:
    def test_removes_tags(self):
        assert strip_tags("<b>жирный</b> текст") == "жирный текст"

    def test_unescapes_entities(self):
        assert strip_tags("a &amp; b") == "a & b"

    def test_entity_order(self):
        """&amp;lt; должен развернуться в &lt;, а не в <."""
        assert strip_tags("&amp;lt;") == "&lt;"

    def test_plain_text_unchanged(self):
        assert strip_tags("без тегов") == "без тегов"
