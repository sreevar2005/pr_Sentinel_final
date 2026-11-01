from prscreen.sanitize import visible


def test_control_and_invisible_characters_become_escapes():
    assert visible("a\x1b[31mb") == "a\\u001b[31mb"
    assert visible("x\u202ey") == "x\\u202ey"
    assert visible("zero\u200bwidth") == "zero\\u200bwidth"
    assert visible("line\nbreak\u2028sep") == "line\\u000abreak\\u2028sep"
    assert visible("bad\udcffbyte") == "bad\\udcffbyte"


def test_ordinary_text_is_unchanged():
    assert visible("café 😀 مرحبا") == "café 😀 مرحبا"
    assert visible("a\tb") == "a    b"


def test_limit_truncates_after_escaping():
    assert visible("abcdef", limit=4) == "abc…"
    assert visible("abc", limit=4) == "abc"
