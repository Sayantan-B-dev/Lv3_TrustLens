"""Investigation API."""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from pymongo import DESCENDING
from pymongo.database import Database

from ..config import Settings, get_settings
from ..db import get_db
from ..intelligence.normalize import (
    InvalidInput,
    detect_input_type,
    normalize_url,
    redact_url_for_display,
)
from ..intelligence.pipeline import CHECK_CATALOG, default_checks
from ..intelligence.risk import RISK_CLASSES, RISK_DEFINITIONS
from ..models import new_feedback, new_investigation, utcnow
from ..security.redaction import redact_text
from ..services.jobs import enqueue_investigation
from ..services.reports import build_report_payload
from .automation import get_or_create as _automation
from .deps import Principal, audit, get_principal, owned_investigation, require_rate_limit
from .serializers import serialize_investigation

router = APIRouter(prefix="/investigations", tags=["investigations"])


class SubmitIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input: str = Field(min_length=1)
    input_type: Literal["auto", "url", "message"] = "auto"
    mode: Literal["automatic", "manual"] | None = None
    checks: list[str] | None = None


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checks: list[str] | None = None


class FeedbackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["helpful", "false_positive", "missed_threat", "report_abuse"]
    comment: str | None = Field(default=None, max_length=1000)


def normalise_checks(raw: list[str] | None, input_type: str) -> list[str]:
    allowed = {key for key in CHECK_CATALOG if key != "message.heuristics" or input_type == "message"}
    if not raw:
        return default_checks(input_type)
    unknown = [item for item in raw if item not in allowed]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown check(s): {', '.join(unknown[:5])}")
    if input_type == "message" and "message.heuristics" not in raw:
        raw = ["message.heuristics", *raw]
    ordered = [key for key in CHECK_CATALOG if key in raw]
    return ordered or default_checks(input_type)


def _load_children(investigation: dict):
    checks = sorted(
        investigation.get("checks") or [],
        key=lambda item: item.get("id", 0),
    )
    indicators = list(investigation.get("indicators") or [])
    reports = sorted(
        investigation.get("reports") or [],
        key=lambda item: item.get("created_at") or utcnow(),
        reverse=True,
    )
    return checks, indicators, reports


@router.post("", status_code=202)
def submit(
    payload: SubmitIn,
    request: Request,
    response: Response,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
    settings: Settings = Depends(get_settings),
):
    require_rate_limit(request, settings, strict=True)

    raw = payload.input.strip()
    if not raw:
        raise HTTPException(status_code=422, detail="Input is empty.")
    if len(raw) > settings.max_input_chars:
        raise HTTPException(
            status_code=422,
            detail=f"Input is too long (maximum {settings.max_input_chars} characters).",
        )

    input_type = payload.input_type
    if input_type == "auto":
        try:
            input_type = detect_input_type(raw)
        except InvalidInput as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    if input_type == "url":
        try:
            info = normalize_url(raw)
        except InvalidInput as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        stored_input = info.url
        display = redact_url_for_display(info.url)
    else:
        stored_input = raw[: settings.max_input_chars]
        display = redact_text(raw[:160]) or "pasted message"

    checks = normalise_checks(payload.checks, input_type)
    automation = _automation(db, principal)
    mode = payload.mode or automation.get("mode", "automatic")
    paused = bool(automation.get("paused", False))
    should_queue = mode == "automatic" and not paused

    days = (
        settings.user_retention_days
        if principal.kind == "user"
        else settings.anonymous_retention_days
    )
    investigation = new_investigation(
        owner_kind=principal.kind,
        owner_id=principal.id,
        input_type=input_type,
        input_value=stored_input,
        display_value=display,
        mode=mode,
        status="queued" if should_queue else "draft",
        checks_requested=checks,
        expires_at=utcnow() + timedelta(days=days),
    )
    db.investigations.insert_one(investigation)

    queued = False
    if should_queue:
        enqueue_investigation(
            db,
            investigation,
            idempotency_key=f"investigation:{investigation['_id']}:initial",
            settings=settings,
        )
        queued = True

    audit(
        db,
        principal,
        "investigation.created",
        target=investigation["_id"],
        detail={"input_type": input_type, "mode": mode, "queued": queued},
    )
    return {
        "investigation": serialize_investigation(investigation, include_checks=False),
        "queued": queued,
        "paused": paused,
        "message": (
            "Investigation queued."
            if queued
            else "Saved. Manual mode or paused automation: run checks when ready."
        ),
    }


@router.get("")
def history(
    limit: int = 12,
    offset: int = 0,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    limit = max(1, min(limit, 50))
    offset = max(0, offset)
    query = {"owner_kind": principal.kind, "owner_id": principal.id}
    total = db.investigations.count_documents(query)
    rows = (
        db.investigations.find(query)
        .sort([("created_at", DESCENDING)])
        .skip(offset)
        .limit(limit)
    )
    return {
        "items": [
            serialize_investigation(row, include_checks=False)
            for row in rows
        ],
        "total": int(total),
        "limit": limit,
        "offset": offset,
    }


@router.get("/{investigation_id}")
def detail(
    investigation_id: str,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    investigation = owned_investigation(db, principal, investigation_id)
    checks, indicators, reports = _load_children(investigation)
    return serialize_investigation(
        investigation, checks=checks, indicators=indicators, reports=reports
    )


@router.post("/{investigation_id}/run", status_code=202)
def run(
    investigation_id: str,
    request: Request,
    payload: RunIn | None = None,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
    settings: Settings = Depends(get_settings),
):
    require_rate_limit(request, settings, strict=True)
    investigation = owned_investigation(db, principal, investigation_id)
    if investigation.get("status") in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="This investigation is already running.")

    checks = normalise_checks(
        payload.checks if payload else None, investigation.get("input_type", "url")
    )
    now = utcnow()
    db.investigations.update_one(
        {"_id": investigation["_id"]},
        {
            "$set": {
                "checks_requested": checks,
                "status": "queued",
                "error": None,
                "updated_at": now,
            }
        },
    )
    investigation.update({"checks_requested": checks, "status": "queued", "error": None})

    enqueue_investigation(
        db,
        investigation,
        idempotency_key=f"investigation:{investigation['_id']}:run:{now.isoformat()}",
        settings=settings,
    )
    audit(db, principal, "investigation.queued", target=investigation["_id"], detail={"checks": checks})
    return {"queued": True, "investigation": serialize_investigation(investigation, include_checks=False)}


@router.delete("/{investigation_id}", status_code=204)
def delete(
    investigation_id: str,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    investigation = owned_investigation(db, principal, investigation_id)
    db.investigations.delete_one({"_id": investigation["_id"]})
    db.jobs.delete_many({"investigation_id": investigation["_id"]})
    audit(db, principal, "investigation.deleted", target=investigation_id)
    return Response(status_code=204)


@router.get("/{investigation_id}/export")
def export(
    investigation_id: str,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    investigation = owned_investigation(db, principal, investigation_id)
    payload = build_report_payload(investigation)
    import json

    body = json.dumps(payload, indent=2, ensure_ascii=False)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="trustlens-{investigation["_id"][:8]}.json"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/{investigation_id}/feedback", status_code=201)
def feedback(
    investigation_id: str,
    payload: FeedbackIn,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    investigation = owned_investigation(db, principal, investigation_id)
    if payload.kind == "report_abuse" and not (payload.comment or "").strip():
        raise HTTPException(status_code=422, detail="Describe the abuse in the comment field.")
    record = new_feedback(
        investigation_id=investigation["_id"],
        owner_key=f"{principal.kind}:{principal.id}",
        kind=payload.kind,
        comment=redact_text(payload.comment or "")[:1000] or None,
    )
    db.feedback.insert_one(record)
    audit(db, principal, "feedback.created", target=investigation["_id"], detail={"kind": payload.kind})
    return {"id": record["_id"], "status": record["status"]}


@router.get("/meta/checks")
def checks_meta():
    return {
        "checks": CHECK_CATALOG,
        "defaults": {"url": default_checks("url"), "message": default_checks("message")},
        "risk_classes": [
            {"name": name, "definition": RISK_DEFINITIONS[name]} for name in RISK_CLASSES
        ],
        "ruleset_version": "trustlens-rules-v1",
    }
