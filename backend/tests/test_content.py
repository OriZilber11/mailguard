from app.analyzers.content import analyze
from app.parsing import ParsedMessage, parse_headers


def ids(text="", html="", subject=""):
    return [s.id for s in analyze(ParsedMessage(parse_headers(f"Subject: {subject}\r\n"), text, html))]


def test_clean():
    assert ids("Lunch at noon?") == []


def test_credential_and_urgency():
    assert ids("Please verify your password immediately") == ["CONTENT_CREDENTIAL_REQUEST", "CONTENT_URGENCY"]


def test_form_and_hidden():
    assert ids(html='<form><input type="password"></form><span style="display:none">x</span>') == [
        "CONTENT_HTML_FORM", "CONTENT_HIDDEN_TEXT"]


def test_financial_in_subject():
    assert ids(subject="Our new bank details") == ["CONTENT_FINANCIAL_REQUEST"]
