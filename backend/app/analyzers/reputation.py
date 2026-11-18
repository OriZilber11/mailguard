from pathlib import Path
from urllib.parse import urlsplit

from app.analyzers.links import _collect, defang
from app.models import Signal
from app.parsing import ParsedMessage

_DATA = Path(__file__).parent.parent / "data"


def _load(name: str) -> frozenset[str]:
    lines = (_DATA / name).read_text().splitlines()
    return frozenset(x.strip().lower() for x in lines if x.strip() and not x.startswith("#"))


BAD_DOMAINS, BAD_HASHES = _load("bad_domains.txt"), _load("bad_hashes.txt")


def _is_bad(host: str) -> bool:
    """True if the host or any parent domain is listed (a.b.evil.test -> b.evil.test -> evil.test)."""
    labels = host.split(".")
    return any(".".join(labels[i:]) in BAD_DOMAINS for i in range(len(labels)))


def analyze(msg: ParsedMessage) -> list[Signal]:
    signals = []
    hosts = {(urlsplit(u).hostname or "").lower() for u, _ in _collect(msg)}
    for host in sorted(h for h in hosts if _is_bad(h)):
        signals.append(Signal(id="REP_BAD_DOMAIN", severity="critical", title="Link to a known malicious site",
                              explanation=f"{defang(host)} is on the threat-intel blocklist."))
    for a in msg.attachments:
        if a.sha256.lower() in BAD_HASHES:
            signals.append(Signal(id="REP_BAD_HASH", severity="critical", title="Known malicious file",
                                  explanation=f"{a.filename} matches a known malware hash."))
    return signals
