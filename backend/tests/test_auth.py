import pytest
from fastapi import HTTPException

from app import auth
from app.main import app


def status(header=""):
    with pytest.raises(HTTPException) as e:
        auth.require_google_user(header)
    return e.value.status_code


def test_unconfigured_fails_closed(monkeypatch):
    monkeypatch.delenv("GOOGLE_AUDIENCE", raising=False)
    assert status("Bearer x") == 503


def test_missing_token_401(monkeypatch):
    monkeypatch.setenv("GOOGLE_AUDIENCE", "aud")
    assert status() == 401


def test_invalid_token_401(monkeypatch):
    monkeypatch.setenv("GOOGLE_AUDIENCE", "aud")
    assert status("Bearer junk") == 401


def test_valid_token_returns_email(monkeypatch):
    monkeypatch.setenv("GOOGLE_AUDIENCE", "aud")
    monkeypatch.setattr(auth.id_token, "verify_oauth2_token", lambda *a: {"email": "u@x.com"})
    assert auth.require_google_user("Bearer ok") == "u@x.com"


def test_analyze_route_is_protected():
    route = next(r for r in app.routes if getattr(r, "path", "") == "/v1/analyze")
    assert any(d.call is auth.require_google_user for d in route.dependant.dependencies)
