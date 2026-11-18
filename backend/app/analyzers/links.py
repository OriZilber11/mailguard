import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.domains import has_public_suffix, registrable_domain
from app.models import Signal
from app.parsing import ParsedMessage

MAX_LINKS = 200
_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_DOMAIN_IN_TEXT = re.compile(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", re.IGNORECASE)


class _Anchors(HTMLParser):
    """Collects (href, visible text) for every <a>. Stdlib parser: never executes anything."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def _collect(msg: ParsedMessage) -> list[tuple[str, str]]:
    parser = _Anchors()
    parser.feed(msg.html)
    links = parser.links
    links += [(u, "") for u in _URL_IN_TEXT.findall(msg.text)]
    return links[:MAX_LINKS]


def analyze(msg: ParsedMessage) -> list[Signal] | None:
    found: dict[str, Signal] = {}

    for href, text in _collect(msg):
        try:
            parts = urlsplit(href)
            host = (parts.hostname or "").lower()
            user = parts.username
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not host:
            continue

        if user and "." in user:
            found.setdefault("LINK_USERINFO_TRICK", Signal(
                id="LINK_USERINFO_TRICK", severity="high",
                title="Link hides its real destination",
                explanation=f"The link {defang(href[:80])} starts with a fake domain, but really goes to {defang(host)}."))

        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip:
            found.setdefault("LINK_IP_LITERAL", Signal(
                id="LINK_IP_LITERAL", severity="high",
                title="Link goes to a raw IP address",
                explanation=f"The link points to {defang(host)} instead of a normal website name."))
            continue

        shown = _DOMAIN_IN_TEXT.search(text)
        if shown and has_public_suffix(shown.group(1)):
            if registrable_domain(shown.group(1)) != registrable_domain(host):
                found.setdefault("LINK_TEXT_MISMATCH", Signal(
                    id="LINK_TEXT_MISMATCH", severity="high",
                    title="Link text shows a different site than the real destination",
                    explanation=f"The link says {defang(shown.group(1))} but goes to {defang(host)}."))
    return list(found.values())
