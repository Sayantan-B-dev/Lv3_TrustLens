"""Durable, MongoDB-backed job queue with leases and bounded retries."""

from __future__ import annotations

from datetime import timedelta

from pymongo import ASCENDING, ReturnDocument
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from ..config import Settings
from ..models import new_job, utcnow
from ..security.redaction import safe_error


def enqueue_investigation(
    db: Database,
    investigation: dict,
    *,
    idempotency_key: str | None = None,
    settings: Settings | None = None,
) -> dict:
    from ..config import get_settings

    settings = settings or get_settings()
    key = idempotency_key or f"investigation:{investigation['_id']}:{investigation.get('status')}"
    key = key[:191]
    existing = db.jobs.find_one({"idempotency_key": key})
    if existing is not None:
        return existing
    job = new_job(
        investigation_id=investigation["_id"],
        idempotency_key=key,
        max_attempts=settings.job_max_attempts,
    )
    try:
        db.jobs.insert_one(job)
    except DuplicateKeyError:  # pragma: no cover - concurrent enqueue
        existing = db.jobs.find_one({"idempotency_key": key})
        if existing is not None:
            return existing
        raise
    return job


def claim_job(db: Database, settings: Settings) -> dict | None:
    now = utcnow()
    job = db.jobs.find_one_and_update(
        {"status": "queued", "available_at": {"$lte": now}},
        {
            "$set": {
                "status": "running",
                "lease_expires_at": now + timedelta(seconds=settings.worker_lease_seconds),
                "updated_at": now,
            },
            "$inc": {"attempts": 1},
        },
        sort=[("created_at", ASCENDING)],
        return_document=ReturnDocument.AFTER,
    )
    if job is None:
        return None
    if job.get("investigation_id"):
        db.investigations.update_one(
            {"_id": job["investigation_id"]},
            {"$set": {"status": "running", "started_at": now}},
        )
    return job


def complete_job(db: Database, job: dict) -> None:
    db.jobs.update_one(
        {"_id": job["_id"]},
        {
            "$set": {
                "status": "succeeded",
                "lease_expires_at": None,
                "last_error": None,
                "updated_at": utcnow(),
            }
        },
    )


def fail_job(db: Database, job: dict, error: BaseException, settings: Settings) -> str:
    message = safe_error(error, 500)
    attempts = int(job.get("attempts") or 0)
    max_attempts = int(job.get("max_attempts") or settings.job_max_attempts)
    now = utcnow()

    if attempts >= max_attempts:
        status = "failed"
        updates = {
            "status": status,
            "last_error": message,
            "lease_expires_at": None,
            "updated_at": now,
        }
        if job.get("investigation_id"):
            db.investigations.update_one(
                {"_id": job["investigation_id"]},
                {
                    "$set": {
                        "status": "failed",
                        "error": message,
                        "completed_at": now,
                    }
                },
            )
    else:
        status = "queued"
        backoff = min(settings.job_retry_base_seconds * (2 ** (attempts - 1)), 600)
        updates = {
            "status": status,
            "last_error": message,
            "available_at": now + timedelta(seconds=backoff),
            "lease_expires_at": None,
            "updated_at": now,
        }
        if job.get("investigation_id"):
            db.investigations.update_one(
                {"_id": job["investigation_id"], "status": "running"},
                {"$set": {"status": "queued"}},
            )

    db.jobs.update_one({"_id": job["_id"]}, {"$set": updates})
    return status


def recover_expired_leases(db: Database, settings: Settings) -> int:
    now = utcnow()
    expired = db.jobs.find({"status": "running", "lease_expires_at": {"$lt": now}})
    recovered = 0
    for job in expired:
        attempts = int(job.get("attempts") or 0)
        max_attempts = int(job.get("max_attempts") or settings.job_max_attempts)
        if attempts >= max_attempts:
            status = "failed"
            message = "Worker lease expired after the maximum number of attempts."
            if job.get("investigation_id"):
                db.investigations.update_one(
                    {"_id": job["investigation_id"]},
                    {"$set": {"status": "failed", "error": message, "completed_at": now}},
                )
            updates = {
                "status": status,
                "last_error": message,
                "lease_expires_at": None,
                "updated_at": now,
            }
        else:
            updates = {
                "status": "queued",
                "available_at": now,
                "last_error": "Recovered after an expired worker lease.",
                "lease_expires_at": None,
                "updated_at": now,
            }
        db.jobs.update_one({"_id": job["_id"]}, {"$set": updates})
        recovered += 1
    return recovered


def queue_depth(db: Database) -> dict:
    counts: dict[str, int] = {}
    for status in db.jobs.distinct("status"):
        if status:
            counts[str(status)] = db.jobs.count_documents({"status": status})
    return counts
