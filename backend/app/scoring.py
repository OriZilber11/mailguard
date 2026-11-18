from collections import Counter
from typing import NamedTuple

from app.models import Signal, Verdict


class Decision(NamedTuple):
    verdict: Verdict
    score: int | None  # None = could not be scored (inconclusive)


def decide(signals: list[Signal], core_failed: bool) -> Decision:
    """Ordered yes/no rules, the first 'yes' wins. It fixes BOTH verdict and score, so they cannot disagree.
    No arithmetic: the score is a class label. Info/trust signals are ignored."""
    n = Counter(s.severity for s in signals)
    rules = [
        (n["critical"] >= 1, "malicious", 100),
        (n["high"] >= 2,     "malicious", 90),
        (n["high"] == 1,     "suspicious", 60),
        (n["medium"] >= 1,   "suspicious", 40),
        (core_failed,        "inconclusive", None),  # a core check could not run: never a false Safe
        (n["low"] >= 1,      "safe", 10),
        (True,               "safe", 0),
    ]
    return Decision(*next(r[1:] for r in rules if r[0]))
