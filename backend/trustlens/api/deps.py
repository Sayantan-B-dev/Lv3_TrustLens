"""Authentication/ownership and cross-cutting API dependencies."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import timedelta, timezone

from fastapi import Depends, HTTPException, Request, Response
from pymongo.database import Database

from ..config import Settings, get_settings
from ..db import get_db
from ..models import new_audit_event, new_session, utcnow
from ..security.ratelimit import limiter
from ..security.sessions import sign_payload, unsign_payload

SESSION_COOKIE = "tl_session"
USER_COOKIE = "tl_user"
OAUTH_STATE_COOKIE = "tl_oauth_state"


@dataclass
class Principal:
    kind: str
    id: str
    email: str | None = None
    name: str | None = None


def _aware(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def get_principal(
    request: Request,
    response: Response,
    db: Database = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    max_age = settings.session_days * 86400

    user_payload = unsign_payload(request.cookies.get(USER_COOKIE), max_age)
    if user_payload and user_payload.get("uid"):
        user = db.users.find_one({"_id": str(user_payload["uid"])})
        if user is not None:
            db.users.update_one({"_id": user["_id"]}, {"$set": {"last_seen_at": utcnow()}})
            return Principal("user", user["_id"], user.get("email"), user.get("name"))

    if not settings.anonymous_access_enabled:
        raise HTTPException(status_code=401, detail="Sign-in is required for this deployment.")

    session_payload = unsign_payload(request.cookies.get(SESSION_COOKIE), max_age)
    anonymous: dict | None = None
    if session_payload and session_payload.get("sid"):
        anonymous = db.sessions.find_one({"_id": str(session_payload["sid"])})
        if anonymous is not None and _aware(anonymous.get("expires_at")) < utcnow():
            anonymous = None
    if anonymous is None:
        anonymous = new_session(expires_at=utcnow() + timedelta(days=settings.session_days))
        db.sessions.insert_one(anonymous)
    else:
        db.sessions.update_one(
            {"_id": anonymous["_id"]}, {"$set": {"last_seen_at": utcnow()}}
        )

    token = sign_payload({"sid": anonymous["_id"], "iat": int(time.time())})
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_days * 86400,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )
    return Principal("anonymous", anonymous["_id"])


def set_user_cookie(response: Response, user_id: str, settings: Settings) -> None:
    response.set_cookie(
        USER_COOKIE,
        sign_payload({"uid": user_id, "iat": int(time.time())}),
        max_age=settings.session_days * 86400,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )


def owner_key(principal: Principal) -> str:
    return f"{principal.kind}:{principal.id}"


def require_rate_limit(request: Request, settings: Settings, *, strict: bool = False) -> None:
    host = request.client.host if request.client else "unknown"
    limit = (
        settings.rate_limit_per_minute if strict else settings.general_rate_limit_per_minute
    )
    allowed, retry_after = limiter.allow(f"{host}:{request.url.path}:{int(strict)}", limit)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait and try again.",
            headers={"Retry-After": str(retry_after)},
        )


def owned_investigation(db: Database, principal: Principal, investigation_id: str) -> dict:
    investigation = db.investigations.find_one({"_id": investigation_id})
    if (
        investigation is None
        or investigation.get("owner_kind") != principal.kind
        or investigation.get("owner_id") != principal.id
    ):
        # Same response for missing and foreign records: no existence leaks.
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation


def audit(
    db: Database,
    principal: Principal,
    action: str,
    *,
    target: str = "",
    detail: dict | None = None,
) -> None:
    db.audit_events.insert_one(
        new_audit_event(
            actor_kind=principal.kind,
            actor_id=principal.id,
            action=action,
            target=target,
            detail=detail or {},
        )
    )
