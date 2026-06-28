import logging

from xsscane.core.csrf import CsrfManager

m = CsrfManager(None, logging.getLogger("t"))


def test_is_token_by_keyword():
    assert m.is_token("csrf_token", "abc")
    assert m.is_token("__RequestVerificationToken", "x")
    assert m.is_token("authenticity_token", "y")


def test_is_token_by_entropy():
    assert m.is_token("h", "9f8a7b6c5d4e3f2a1b0c9d8e")


def test_benign_hidden_is_not_a_token():
    assert not m.is_token("redirect", "/dashboard")
    assert not m.is_token("page", "2")
    assert not m.is_token("next", "home")


def test_parse_keeps_hidden_token_and_text_fields():
    html = (
        '<form action="/submit" method="post">'
        '<input type="hidden" name="csrf_token" value="3b1fdeadbeefcafe1234">'
        '<input type="hidden" name="redirect" value="/done">'
        '<textarea name="comment"></textarea><input type="submit"></form>'
    )
    form = m._parse(html, "http://t/")[0]
    assert form["has_token"]
    assert "csrf_token" in form["hidden"] and "redirect" in form["hidden"]
    assert list(form["text_fields"]) == ["comment"] and form["method"] == "POST"
