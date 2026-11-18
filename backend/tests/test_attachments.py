import base64

from app.analyzers.attachments import analyze
from app.models import Attachment
from app.parsing import ParsedMessage, parse_headers


def att(name, magic=b"\x00" * 16):
    return Attachment(filename=name, content_type="x", size=1, sha256="ab",
                      magic_b64=base64.b64encode(magic).decode())


def ids(*atts):
    r = analyze(ParsedMessage(parse_headers(""), attachments=list(atts)))
    return None if r is None else [s.id for s in r]


def test_no_attachments_is_skipped():
    assert ids() is None


def test_normal_pdf():
    assert ids(att("report.pdf", b"%PDF-1.7" + b"\x00" * 8)) == []


def test_dangerous_type():
    assert ids(att("setup.exe", b"MZ" + b"\x00" * 14)) == ["ATT_DANGEROUS_TYPE"]


def test_double_extension():
    assert ids(att("invoice.pdf.exe", b"MZ" + b"\x00" * 14)) == ["ATT_DANGEROUS_TYPE", "ATT_DOUBLE_EXTENSION"]


def test_type_mismatch_pdf_is_really_exe():
    assert ids(att("invoice.pdf", b"MZ" + b"\x00" * 14)) == ["ATT_TYPE_MISMATCH"]


def test_html_and_macro_are_medium():
    assert ids(att("login.html"), att("budget.xlsm", b"PK\x03\x04" + b"\x00" * 12)) == ["ATT_HTML_ATTACHMENT", "ATT_MACRO_DOC"]


def test_docx_zip_magic_is_fine():
    assert ids(att("a.docx", b"PK\x03\x04" + b"\x00" * 12)) == []


def test_bad_base64_does_not_crash():
    a = Attachment(filename="a.pdf", content_type="x", size=1, sha256="ab", magic_b64="!!!")
    assert ids(a) == []
