from app.analyzers.links import analyze
from app.parsing import ParsedMessage, parse_headers


def ids(html="", text=""):
    return [s.id for s in analyze(ParsedMessage(parse_headers(""), text, html))]


def test_no_links():
    assert ids("<p>hello</p>") == []


def test_normal_link():
    assert ids('<a href="https://www.paypal.com/login">paypal.com</a>') == []


def test_generic_text_is_fine():
    assert ids('<a href="https://evil.top/x">Click here</a>') == []


def test_text_mismatch():
    assert ids('<a href="https://evil.top/x">www.paypal.com</a>') == ["LINK_TEXT_MISMATCH"]


def test_text_mismatch_with_scheme():
    assert ids('<a href="https://evil.top/x">https://paypal.com/login</a>') == ["LINK_TEXT_MISMATCH"]


def test_subdomain_same_site_ok():
    assert ids('<a href="https://accounts.google.com/x">google.com</a>') == []


def test_ip_literal():
    assert ids('<a href="http://192.168.1.5/login">Sign in</a>') == ["LINK_IP_LITERAL"]


def test_userinfo_trick_in_text_body():
    assert ids(text="go to https://paypal.com@evil.top/login now") == ["LINK_USERINFO_TRICK"]


def test_mailto_and_bad_urls_ignored():
    assert ids('<a href="mailto:a@b.com">a.com</a><a href="http://[bad">x</a>') == []


def test_each_signal_once():
    html = '<a href="https://evil.top/1">paypal.com</a><a href="https://evil.top/2">paypal.com</a>'
    assert ids(html) == ["LINK_TEXT_MISMATCH"]
