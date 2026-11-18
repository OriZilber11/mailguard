from fastapi import Depends, FastAPI

from app.analyzers import attachments, authentication, content, llm, links, reputation, sender
from app.auth import require_google_user
from app.models import AnalyzeRequest, AnalyzeResponse, Signal
from app.parsing import ParsedMessage, parse_headers
from app.scoring import decide

ENGINE_VERSION = "2.1.0"

ANALYZERS = {"authentication": authentication.analyze, "sender": sender.analyze, "links": links.analyze,
              "attachments": attachments.analyze, "content": content.analyze,
              "reputation": reputation.analyze}

CORE_ANALYZERS = {"authentication", "sender", "links"}

SUMMARY = {
    "safe": "No risk found by the checks that ran.",
    "suspicious": "Some checks failed. Be careful with links and attachments.",
    "malicious": "Multiple serious checks failed. Do not interact with this email.",
    "inconclusive": "Some checks could not run. Treat this email with caution.",
}

app = FastAPI(title="MailGuard API", docs_url=None, redoc_url=None)


@app.get("/healthz")
def healthz() -> dict:
    """Unauthenticated liveness check. Returns nothing else, by design."""
    return {"status": "ok", "engine_version": ENGINE_VERSION}


@app.post("/v1/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_google_user)])
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    msg = ParsedMessage(parse_headers(req.headers_raw), req.body_text, req.body_html, req.attachments)

    signals: list[Signal] = []
    core_failed = False
    for name, run in ANALYZERS.items():
        try:
            result = run(msg)
        except Exception:  # a broken analyzer must never silently lower the result
            core_failed = True
            continue
        if result is None and name in CORE_ANALYZERS:  # core checks are never "not applicable"
            core_failed = True
        signals.extend(result or [])

    extra, ai_summary = llm.assess(msg, signals)  # advisory: can only add a medium signal
    signals.extend(extra)
    verdict = decide(signals, core_failed)
    return AnalyzeResponse(
        engine_version=ENGINE_VERSION,
        verdict=verdict,
        summary=ai_summary or SUMMARY[verdict],
        signals=signals,
    )
