from app.analyzers.authentication import analyze
from app.models import Signal
from app.parsing import ParsedMessage, parse_headers
from app.scoring import decide


def sig(sev):
    return Signal(id="X", severity=sev, title="t", explanation="e")


def auth(value):
    return analyze(ParsedMessage(parse_headers("Authentication-Results: mx.google.com;\r\n " + value + "\r\n")))


def test_dmarc_fail_is_high():
    assert [s.id for s in auth("spf=pass dkim=pass dmarc=fail")] == ["AUTH_DMARC_FAIL"]


def test_all_pass():
    assert [s.id for s in auth("spf=pass dkim=pass dmarc=pass")] == ["AUTH_ALIGNED_PASS"]


def test_softfail_spf():
    assert [s.id for s in auth("spf=softfail dkim=pass dmarc=pass")][0] == "AUTH_SPF_FAIL"


def test_missing_header_is_skipped():
    assert analyze(ParsedMessage(parse_headers("From: a@b.com\r\n"))) is None


def test_verdict_rules():
    assert decide([], False) == "safe"
    assert decide([sig("medium")], False) == "safe"
    assert decide([sig("medium"), sig("medium")], False) == "suspicious"
    assert decide([sig("high")], False) == "suspicious"
    assert decide([sig("high"), sig("high")], False) == "malicious"
    assert decide([sig("critical")], False) == "malicious"
    assert decide([], False, confirmed=True) == "malicious"
    assert decide([], True) == "inconclusive"
    assert decide([sig("high")], True) == "suspicious"
