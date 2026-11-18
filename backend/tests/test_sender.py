from app.analyzers.sender import analyze
from app.parsing import ParsedMessage, parse_headers


def run(headers):
    return analyze(ParsedMessage(parse_headers(headers)))


def ids(headers):
    return [s.id for s in run(headers)]


def test_clean_sender():
    assert ids("From: Bob <bob@example.com>\r\nReply-To: bob@example.com\r\n") == []


def test_subdomain_is_not_a_mismatch():
    assert ids("From: a@news.example.com\r\nReply-To: b@example.com\r\n") == []


def test_replyto_mismatch():
    assert ids("From: a@example.com\r\nReply-To: a@gmail.com\r\n") == ["SENDER_REPLYTO_MISMATCH"]


def test_returnpath_mismatch_low():
    assert ids("From: a@example.com\r\nReturn-Path: <bounce@mailer.net>\r\n") == ["SENDER_RETURNPATH_MISMATCH"]


def test_display_name_with_other_email():
    assert ids('From: "ceo@company.com" <evil@bad.top>\r\n') == ["SENDER_DISPLAYNAME_EMAIL"]


def test_display_name_with_same_email_ok():
    assert ids('From: "bob@example.com" <bob@example.com>\r\n') == []


def test_missing_from_is_skipped():
    assert run("Subject: hi\r\n") is None
