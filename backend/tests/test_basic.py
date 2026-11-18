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


import pytest

# (signal severities, core_failed) -> (verdict, score). One row per rule plus its boundaries.
@pytest.mark.parametrize("sevs,core_failed,expected", [
    ([], False, ("safe", 0)),
    (["info"], False, ("safe", 0)),
    (["trust"], False, ("safe", 0)),
    (["low"], False, ("safe", 10)),
    (["low", "low", "low"], False, ("safe", 10)),
    (["medium"], False, ("suspicious", 40)),
    (["medium", "medium", "low"], False, ("suspicious", 40)),
    (["high"], False, ("suspicious", 60)),
    (["high", "medium", "low"], False, ("suspicious", 60)),
    (["high", "high"], False, ("malicious", 90)),
    (["high", "high", "high", "medium"], False, ("malicious", 90)),
    (["critical"], False, ("malicious", 100)),
    (["critical", "high", "high"], False, ("malicious", 100)),
    ([], True, ("inconclusive", None)),
    (["info"], True, ("inconclusive", None)),
    (["low"], True, ("inconclusive", None)),
    (["medium"], True, ("suspicious", 40)),
    (["high"], True, ("suspicious", 60)),
    (["critical"], True, ("malicious", 100)),
])
def test_verdict_and_score(sevs, core_failed, expected):
    assert tuple(decide([sig(s) for s in sevs], core_failed)) == expected


def test_score_bands_never_cross_verdicts():
    bands = {"safe": range(0, 31), "suspicious": range(31, 71), "malicious": range(71, 101)}  # card color bands
    for combo in ([], ["low"], ["medium"], ["high"], ["high", "high"], ["critical"]):
        d = decide([sig(s) for s in combo], False)
        assert d.score in bands[d.verdict]
