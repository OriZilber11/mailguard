from app.models import Signal, Verdict


def decide(signals: list[Signal], core_failed: bool, confirmed: bool = False) -> Verdict:
    """Boolean verdict rules (design section 6). The only place the rules live."""
    count = {s: sum(1 for x in signals if x.severity == s) for s in ("medium", "high", "critical")}

    if confirmed or count["critical"] >= 1 or count["high"] >= 2:
        return "malicious"
    if count["high"] == 1 or count["medium"] >= 2:
        return "suspicious"
    if core_failed:
        return "inconclusive"
    return "safe"
