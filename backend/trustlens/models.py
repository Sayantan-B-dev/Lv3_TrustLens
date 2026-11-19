"""MongoDB document shapes and factories.

Documents are plain dictionaries: queryable fields stay top-level and
free-form evidence lives in embedded JSON. Investigation documents embed
their checks, indicators and reports, which keeps the common read path to a
single document without pretending this workload is relational.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


def new_user(
    *,
    provider: str,
    subject: str,
    email: str | None = None,
    name: str | None = None,
) -> dict:
    now = utcnow()
    return {
        "_id": new_id(),
        "provider": provider,
        "subject": subject,
        "email": email,
        "name": name,
        "created_at": now,
        "last_seen_at": now,
    }


def new_session(*, expires_at: datetime) -> dict:
    now = utcnow()
    return {
        "_id": new_id(),
        "created_at": now,
        "last_seen_at": now,
        "expires_at": expires_at,
    }


def new_investigation(
    *,
    owner_kind: str,
    owner_id: str,
    input_type: str,
    input_value: str,
    display_value: str,
    mode: str,
    status: str,
    checks_requested: list[str],
    expires_at: datetime,
) -> dict:
    return {
        "_id": new_id(),
        "owner_kind": owner_kind,
        "owner_id": owner_id,
        "input_type": input_type,
        "input_value": input_value,
        "display_value": display_value,
        "mode": mode,
        "status": status,
        "checks_requested": checks_requested,
        "risk_classification": None,
        "score": 0,
        "confidence": None,
        "coverage": None,
        "ruleset_version": "trustlens-rules-v1",
        "summary": None,
        "error": None,
        "ai_provider": None,
        "ai_model": None,
        "ai_used": False,
        "checks_total": 0,
        "checks_completed": 0,
        "checks": [],
        "indicators": [],
        "reports": [],
        "report_seq": 0,
        "created_at": utcnow(),
        "started_at": None,
        "completed_at": None,
        "expires_at": expires_at,
    }


def new_job(
    *,
    investigation_id: str | None,
    idempotency_key: str,
    max_attempts: int,
) -> dict:
    now = utcnow()
    return {
        "_id": new_id(),
        "kind": "investigation",
        "investigation_id": investigation_id,
        "status": "queued",
        "attempts": 0,
        "max_attempts": max_attempts,
        "available_at": now,
        "lease_expires_at": None,
        "last_error": None,
        "idempotency_key": idempotency_key,
        "created_at": now,
        "updated_at": now,
    }


def new_automation(*, owner_key: str, modules: dict[str, bool]) -> dict:
    now = utcnow()
    return {
        "_id": owner_key,
        "owner_key": owner_key,
        "mode": "automatic",
        "paused": False,
        "modules": modules,
        "created_at": now,
        "updated_at": now,
    }


def new_feedback(
    *,
    investigation_id: str,
    owner_key: str,
    kind: str,
    comment: str | None,
) -> dict:
    return {
        "_id": new_id(),
        "investigation_id": investigation_id,
        "owner_key": owner_key,
        "kind": kind,
        "comment": comment,
        "status": "open",
        "created_at": utcnow(),
    }


def new_audit_event(
    *,
    actor_kind: str,
    actor_id: str,
    action: str,
    target: str,
    detail: dict,
) -> dict:
    return {
        "_id": new_id(),
        "actor_kind": actor_kind,
        "actor_id": actor_id,
        "action": action[:64],
        "target": target[:191],
        "detail": detail,
        "created_at": utcnow(),
    }


def new_report(
    *,
    investigation_id: str,
    submitter_kind: str,
    submitter_id: str,
    version: int,
    canonical_version: str,
    payload: dict,
    digest: str,
    report_ref: str,
) -> dict:
    return {
        "id": new_id(),
        "investigation_id": investigation_id,
        "submitter_kind": submitter_kind,
        "submitter_id": submitter_id,
        "version": version,
        "canonical_version": canonical_version,
        "payload": payload,
        "digest": digest,
        "report_ref": report_ref,
        "status": "created",
        "chain_id": None,
        "contract_address": None,
        "tx_hash": None,
        "block_number": None,
        "committed_at": None,
        "last_error": None,
        "created_at": utcnow(),
    }
