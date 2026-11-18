import re
from email.utils import parseaddr

from app.domains import registrable_domain
from app.models import Signal
from app.parsing import ParsedMessage

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _addr(value) -> tuple[str, str]:
    """Returns (display_name, lowercased address) from a header value."""
    name, addr = parseaddr(str(value or ""))
    return name, addr.lower()


def _domain(addr: str) -> str:
    return registrable_domain(addr.rsplit("@", 1)[1]) if "@" in addr else ""


def analyze(msg: ParsedMessage) -> list[Signal] | None:
    name, from_addr = _addr(msg.headers.get("From"))
    if not from_addr or "@" not in from_addr:
        return None  # cannot evaluate the sender at all

    from_domain = _domain(from_addr)
    signals: list[Signal] = []

    _, reply_to = _addr(msg.headers.get("Reply-To"))
    if reply_to and _domain(reply_to) and _domain(reply_to) != from_domain:
        signals.append(Signal(
            id="SENDER_REPLYTO_MISMATCH", severity="medium",
            title="Replies go to a different domain",
            explanation=f"The email is from {from_domain}, but replies would go to {_domain(reply_to)}."))

    _, return_path = _addr(msg.headers.get("Return-Path"))
    if return_path and _domain(return_path) and _domain(return_path) != from_domain:
        signals.append(Signal(
            id="SENDER_RETURNPATH_MISMATCH", severity="low",
            title="Bounce address uses a different domain",
            explanation=f"The technical return address belongs to {_domain(return_path)}, not {from_domain}. Common for bulk mail."))

    shown = {m.lower() for m in _EMAIL_IN_TEXT.findall(name)}
    if shown - {from_addr}:
        signals.append(Signal(
            id="SENDER_DISPLAYNAME_EMAIL", severity="high",
            title="Display name shows a different email address",
            explanation="The sender's name contains an address that is not the real sender, a common spoofing trick."))
    return signals
