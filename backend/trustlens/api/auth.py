"""Optional Google OAuth. No passwords are stored anywhere."""

from __future__ import annotations

import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from ..config import Settings, get_settings
from ..db import get_db
from ..models import new_user, utcnow
from ..security.redaction import safe_error
from .deps import (
    OAUTH_STATE_COOKIE,
    USER_COOKIE,
    Principal,
    get_principal,
    set_user_cookie,
)

router = APIRouter(prefix="/auth", tags=["auth"])

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


@router.get("/me")
def me(
    principal: Principal = Depends(get_principal),
    settings: Settings = Depends(get_settings),
):
    return {
        "authenticated": principal.kind == "user",
        "mode": principal.kind,
        "email": principal.email,
        "name": principal.name,
        "oauth_available": settings.oauth_configured,
        "anonymous_allowed": settings.anonymous_access_enabled,
    }


@router.get("/google/start")
def google_start(settings: Settings = Depends(get_settings)):
    if not settings.oauth_configured:
        raise HTTPException(status_code=503, detail="Google sign-in is not configured on this deployment.")
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    response = RedirectResponse(f"{GOOGLE_AUTH_URL}?{urlencode(params)}", status_code=302)
    response.set_cookie(
        OAUTH_STATE_COOKIE,
        state,
        max_age=600,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )
    return response


@router.get("/google/callback")
def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Database = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    frontend = settings.frontend_url.rstrip("/")
    if not settings.oauth_configured:
        return RedirectResponse(f"{frontend}/?auth=error&reason=unconfigured", status_code=302)
    if error or not code or not state:
        return RedirectResponse(f"{frontend}/?auth=error&reason=denied", status_code=302)
    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not cookie_state or not secrets.compare_digest(cookie_state, state):
        return RedirectResponse(f"{frontend}/?auth=error&reason=state", status_code=302)

    try:
        with httpx.Client(timeout=12, trust_env=False) as client:
            token_response = client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": settings.google_redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            if token_response.status_code >= 400:
                raise RuntimeError(f"token exchange HTTP {token_response.status_code}")
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            if not access_token:
                raise RuntimeError("token response did not include an access token")
            userinfo_response = client.get(
                GOOGLE_USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}
            )
            if userinfo_response.status_code >= 400:
                raise RuntimeError(f"userinfo HTTP {userinfo_response.status_code}")
            info = userinfo_response.json()
    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
        safe_reason = safe_error(exc, 80).replace(" ", "_")
        return RedirectResponse(f"{frontend}/?auth=error&reason={safe_reason}", status_code=302)

    subject = str(info.get("sub") or "")
    if not subject:
        return RedirectResponse(f"{frontend}/?auth=error&reason=no_subject", status_code=302)

    user = db.users.find_one({"provider": "google", "subject": subject})
    if user is None:
        user = new_user(
            provider="google",
            subject=subject,
            email=info.get("email"),
            name=info.get("name"),
        )
        try:
            db.users.insert_one(user)
        except DuplicateKeyError:
            user = db.users.find_one({"provider": "google", "subject": subject})
    else:
        db.users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "email": info.get("email") or user.get("email"),
                    "name": info.get("name") or user.get("name"),
                    "last_seen_at": utcnow(),
                }
            },
        )

    if user is None:  # pragma: no cover - only if a concurrent insert vanished
        return RedirectResponse(f"{frontend}/?auth=error&reason=no_user", status_code=302)

    redirect = RedirectResponse(f"{frontend}/?auth=ok", status_code=302)
    set_user_cookie(redirect, user["_id"], settings)
    redirect.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    return redirect


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(USER_COOKIE, path="/")
    return {"authenticated": False}
