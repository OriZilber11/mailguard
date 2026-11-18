from app.analyzers.reputation import analyze
from app.models import Attachment
from app.parsing import ParsedMessage, parse_headers

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def ids(text="", html="", atts=()):
    return [s.id for s in analyze(ParsedMessage(parse_headers(""), text, html, list(atts)))]


def test_clean():
    assert ids("see https://example.com/a") == []


def test_bad_domain_and_subdomain():
    assert ids("go https://login.evil.test/x") == ["REP_BAD_DOMAIN"]


def test_bad_domain_in_html_link():
    assert ids(html='<a href="http://phish.test/">hi</a>') == ["REP_BAD_DOMAIN"]


def test_bad_hash():
    a = Attachment(filename="x.txt", content_type="text/plain", size=1, sha256=EICAR, magic_b64="AA==")
    assert ids(atts=[a]) == ["REP_BAD_HASH"]
