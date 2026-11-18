import re

from app.models import Signal
from app.parsing import ParsedMessage

_RESULT = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


def analyze(msg: ParsedMessage) -> list[Signal] | None:
    """Reads the Authentication-Results header added by Gmail.
    Returns None (skipped) when the header is absent, [] when it ran and found nothing."""
    header = msg.headers.get("Authentication-Results")  # first = the one Gmail added
    if header is None:
        return None

    results: dict[str, str] = {}
    for name, value in _RESULT.findall(str(header)):
        results.setdefault(name.lower(), value.lower())  # first occurrence wins

    signals: list[Signal] = []
    if results.get("spf") in ("fail", "softfail"):
        signals.append(Signal(id="AUTH_SPF_FAIL", severity="medium",
                              title="SPF check failed",
                              explanation="The sending server is not authorized to send for this domain."))
    if results.get("dkim") == "fail":
        signals.append(Signal(id="AUTH_DKIM_FAIL", severity="medium",
                              title="DKIM signature failed",
                              explanation="The email's digital signature is invalid, so it may have been altered or forged."))
    if results.get("dmarc") == "fail":
        signals.append(Signal(id="AUTH_DMARC_FAIL", severity="high",
                              title="DMARC check failed",
                              explanation="The sender domain's own policy says this email is not legitimate."))
    if results.get("dmarc") == "pass":
        signals.append(Signal(id="AUTH_ALIGNED_PASS", severity="info",
                              title="Sender passed DMARC",
                              explanation="The email is authenticated as coming from the domain it claims."))
    return signals
