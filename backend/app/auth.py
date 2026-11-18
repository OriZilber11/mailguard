import os

from fastapi import Header, HTTPException
from google.auth.transport import requests as g_requests
from google.oauth2 import id_token


def require_google_user(authorization: str = Header(default="")) -> str:
    """Verifies the add-on's Google ID token; returns the caller's email. Fails closed."""
    audience = os.environ.get("GOOGLE_AUDIENCE")
    if not audience:
        raise HTTPException(503, "Server auth is not configured")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "Missing bearer token")
    try:
        claims = id_token.verify_oauth2_token(token, g_requests.Request(), audience)
    except ValueError:  # bad signature, expired, wrong audience
        raise HTTPException(401, "Invalid token")
    return claims.get("email", "")
