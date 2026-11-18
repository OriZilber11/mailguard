import re

from app.models import Signal
from app.parsing import ParsedMessage

# (id, severity, title, explanation, pattern, where) - one row per check; add a row to add a check.
_RULES = [
    ("CONTENT_HTML_FORM", "high", "Email contains a form",
     "Forms and password fields inside an email are used to steal credentials.",
     r"<form\b|<input[^>]+type\s*=\s*[\"']?password", "html"),
    ("CONTENT_CREDENTIAL_REQUEST", "medium", "Asks you to verify credentials",
     "The text asks you to confirm a password or account details.",
     r"(verify|confirm|update|validate|reset)\s+(your\s+)?(password|account|identity|login|credentials)", "text"),
    ("CONTENT_FINANCIAL_REQUEST", "medium", "Asks for money or payment changes",
     "The text mentions wire transfers, gift cards, crypto or changed bank details.",
     r"wire transfer|gift cards?|bitcoin|crypto(currency)?|(new|changed|updated) bank (details|account)", "text"),
    ("CONTENT_URGENCY", "low", "Pressure to act quickly",
     "Urgent wording is a common social-engineering tactic.",
     r"within 24 hours|immediately|account (will be )?(suspended|locked|closed)|urgent action|final notice", "text"),
    ("CONTENT_HIDDEN_TEXT", "low", "Hidden text in the HTML",
     "Invisible text is used to slip past filters.",
     r"display\s*:\s*none|font-size\s*:\s*0(px)?\b|visibility\s*:\s*hidden", "html"),
]
_COMPILED = [(*r[:4], re.compile(r[4], re.I), r[5]) for r in _RULES]


def analyze(msg: ParsedMessage) -> list[Signal]:
    # Plain text is checked against the visible text; if only HTML exists, scan the HTML too.
    text = f"{msg.headers.get('Subject', '')}\n{msg.text or msg.html}"
    return [Signal(id=i, severity=sev, title=t, explanation=e)
            for i, sev, t, e, rx, where in _COMPILED
            if rx.search(msg.html if where == "html" else text)]
