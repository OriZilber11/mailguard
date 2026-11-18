# MailGuard

Gmail add-on that checks the opened email with boolean pass/fail checks and shows a verdict
(Safe, Suspicious, Malicious, Inconclusive) with the evidence behind it. All detection runs in a FastAPI backend;
the add-on only extracts the email and renders the result.

- `design.md` - full design (see "MVP scope" for what is built now)
- `addon/` - Google Apps Script add-on (paste files into script.google.com; set Script Property `BACKEND_URL`)
- `backend/` - FastAPI service

## Built so far
- End-to-end: Gmail add-on -> HTTPS tunnel -> `POST /v1/analyze` -> card in the Gmail sidebar
- Analyzers: authentication (SPF/DKIM/DMARC), sender (Reply-To, Return-Path, display-name spoofing)
- Boolean verdict rules (`backend/app/scoring.py`); a failed core check gives Inconclusive, never a false Safe
- 12 unit tests

## Run the backend
```
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/uvicorn app.main:app --port 8080
```
Expose it with `ngrok http --url=https://<your-domain> 8080`, then set the same URL in the add-on's
`appsscript.json` (`urlFetchWhitelist`) and the `BACKEND_URL` Script Property.

## Next
Link analyzers, attachment checks, Google ID token auth, threat intel, LLM summary.

## LLM review (optional)
With `ANTHROPIC_API_KEY` set, the backend sends the subject and first 4 KB of the body (emails and phone numbers masked)
to the Anthropic API for a plain-language summary and an advisory phishing-intent flag (adds at most one medium signal;
never lowers a verdict). Unset the key or set `LLM_ENABLED=false` to turn it off.
