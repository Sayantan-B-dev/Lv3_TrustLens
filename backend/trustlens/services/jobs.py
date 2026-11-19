"""Durable, database-backed job queue with leases and bounded retries."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Investigation, Job, utcnow
from ..security.redaction import safe_error


def enqueue_investigation(
    session: Session,
    investigation: Investigation,
    *,
    idempotency_key: str | None = None,
    settings: Settings | None = None,
) -> Job:
    from ..config import get_settings

    settings = settings or get_settings()
    key = idempotency_key or f"investigation:{investigation.id}:{investigation.status}"
    existing = session.execute(select(Job).where(Job.idempotency_key == key)).scalar_one_or_none()
    if existing is not None:
        return existing
    job = Job(
        kind="investigation",
        investigation_id=investigation.id,
        status="queued",
        max_attempts=settings.job_max_attempts,
        available_at=utcnow(),
        idempotency_key=key[:191],
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return job


def claim_job(session: Session, settings: Settings) -> Job | None:
    now = utcnow()
    is_postgres = session.bind.dialect.name == "postgresql"

    if is_postgres:
        query = (
            select(Job)
            .where(Job.status == "queued", Job.available_at <= now)
            .order_by(Job.created_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job = session.execute(query).scalar_one_or_none()
        if job is None:
            return None
        job.status = "running"
        job.attempts += 1
        job.lease_expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
        if job.investigation_id:
            session.execute(
                update(Investigation)
                .where(Investigation.id == job.investigation_id)
                .values(status="running", started_at=now)
            )
        session.commit()
        session.refresh(job)
        return job

    candidate = session.execute(
        select(Job)
        .where(Job.status == "queued", Job.available_at <= now)
        .order_by(Job.created_at.asc())
        .limit(1)
    ).scalar_one_or_none()
    if candidate is None:
        return None
    claimed = session.execute(
        update(Job)
        .where(Job.id == candidate.id, Job.status == "queued")
        .values(
            status="running",
            attempts=Job.attempts + 1,
            lease_expires_at=now + timedelta(seconds=settings.worker_lease_seconds),
            updated_at=now,
        )
    )
    session.commit()
    if claimed.rowcount != 1:
        return None
    if candidate.investigation_id:
        session.execute(
            update(Investigation)
            .where(Investigation.id == candidate.investigation_id)
            .values(status="running", started_at=now)
        )
        session.commit()
    session.refresh(candidate)
    return candidate


def complete_job(session: Session, job: Job) -> None:
    job.status = "succeeded"
    job.lease_expires_at = None
    job.last_error = None
    job.updated_at = utcnow()
    session.commit()


def fail_job(session: Session, job: Job, error: BaseException, settings: Settings) -> str:
    message = safe_error(error, 500)
    job.last_error = message
    if job.attempts >= job.max_attempts:
        job.status = "failed"
        job.lease_expires_at = None
        if job.investigation_id:
            investigation = session.get(Investigation, job.investigation_id)
            if investigation is not None:
                investigation.status = "failed"
                investigation.error = message
                investigation.completed_at = utcnow()
    else:
        backoff = min(settings.job_retry_base_seconds * (2 ** (job.attempts - 1)), 600)
        job.status = "queued"
        job.available_at = utcnow() + timedelta(seconds=backoff)
        job.lease_expires_at = None
        if job.investigation_id:
            investigation = session.get(Investigation, job.investigation_id)
            if investigation is not None and investigation.status == "running":
                investigation.status = "queued"
    job.updated_at = utcnow()
    session.commit()
    return job.status


def recover_expired_leases(session: Session, settings: Settings) -> int:
    now = utcnow()
    expired = session.execute(
        select(Job).where(Job.status == "running", Job.lease_expires_at < now)
    ).scalars().all()
    recovered = 0
    for job in expired:
        if job.attempts >= job.max_attempts:
            job.status = "failed"
            job.last_error = "Worker lease expired after the maximum number of attempts."
            if job.investigation_id:
                investigation = session.get(Investigation, job.investigation_id)
                if investigation is not None:
                    investigation.status = "failed"
                    investigation.error = job.last_error
        else:
            job.status = "queued"
            job.available_at = now
            job.last_error = "Recovered after an expired worker lease."
        job.lease_expires_at = None
        recovered += 1
    session.commit()
    return recovered


def queue_depth(session: Session) -> dict:
    rows = session.execute(select(Job.status, Job.id)).all()
    counts: dict[str, int] = {}
    for status, _id in rows:
        counts[status] = counts.get(status, 0) + 1
    return counts
