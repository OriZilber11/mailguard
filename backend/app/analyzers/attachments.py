import base64
import binascii

from app.models import Signal
from app.parsing import ParsedMessage

DANGEROUS = {"exe", "scr", "js", "vbs", "lnk", "iso", "img", "hta", "bat", "ps1", "msi"}
HTML_TYPES = {"html", "htm", "svg"}
MACRO = {"docm", "xlsm", "pptm"}
# Extensions that look harmless; used to spot "invoice.pdf.exe".
BENIGN = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "rtf"}

# First bytes -> real file family.
MAGIC = [
    (b"MZ", "exe"),
    (b"\x7fELF", "exe"),
    (b"%PDF", "pdf"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF8", "gif"),
    (b"PK\x03\x04", "zip"),
]
# What family each extension should be, when we know it.
EXPECTED = {
    "pdf": "pdf", "png": "png", "jpg": "jpg", "jpeg": "jpg", "gif": "gif",
    "zip": "zip", "docx": "zip", "xlsx": "zip", "pptx": "zip",
    "docm": "zip", "xlsm": "zip", "pptm": "zip",
}


def _family(magic_b64: str) -> str | None:
    try:
        data = base64.b64decode(magic_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    for prefix, family in MAGIC:
        if data.startswith(prefix):
            return family
    return None


def _sig(id_: str, severity: str, title: str, explanation: str) -> Signal:
    return Signal(id=id_, severity=severity, title=title, explanation=explanation)


def analyze(msg: ParsedMessage) -> list[Signal] | None:
    if not msg.attachments:
        return None  # not applicable

    found: dict[str, Signal] = {}
    for att in msg.attachments:
        name = att.filename.strip().lower()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""

        if ext in DANGEROUS:
            found.setdefault("ATT_DANGEROUS_TYPE", _sig(
                "ATT_DANGEROUS_TYPE", "high", "Attachment can run programs",
                f"A .{ext} file can execute code on your computer."))
            if len(parts) > 2 and parts[-2] in BENIGN:
                found.setdefault("ATT_DOUBLE_EXTENSION", _sig(
                    "ATT_DOUBLE_EXTENSION", "high", "Attachment disguises its real type",
                    f"The name ends in .{parts[-2]}.{ext}, which makes a program look like a document."))
        elif ext in HTML_TYPES:
            found.setdefault("ATT_HTML_ATTACHMENT", _sig(
                "ATT_HTML_ATTACHMENT", "medium", "Web page attached",
                "HTML attachments are often used to steal passwords with fake login pages."))
        elif ext in MACRO:
            found.setdefault("ATT_MACRO_DOC", _sig(
                "ATT_MACRO_DOC", "medium", "Document can contain macros",
                "Macro-enabled Office files can run code when opened."))

        real = _family(att.magic_b64)
        expected = EXPECTED.get(ext)
        if real and ((expected and real != expected) or (not expected and real == "exe" and ext not in DANGEROUS)):
            found.setdefault("ATT_TYPE_MISMATCH", _sig(
                "ATT_TYPE_MISMATCH", "high", "File type does not match its name",
                f"The file is named .{ext or 'unknown'} but its contents look like a {real} file."))
    return list(found.values())
