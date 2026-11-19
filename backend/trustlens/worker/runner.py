"""Embedded worker loop.

One Render service runs the API and this loop. Work is claimed from the
database with leases, so a crash or restart does not lose queued work.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db import SessionLocal
from ..models import Investigation, WorkerHeartbeat, utcnow
from ..security.redaction import safe_error
from ..services.jobs import claim_job, complete_job, fail_job, recover_expired_leases
from ..intelligence.pipeline import run_pipeline

logger = logging.getLogger("trustlens.worker")


def _heartbeat(session: Session, settings: Settings, *, status: str, error: str | None = None, increment: bool = False) -> None:
    record = session.get(WorkerHeartbeat, settings.worker_name)
    if record is None:
        record = WorkerHeartbeat(
            id=settings.worker_name,
            started_at=utcnow(),
            processed_count=0,
        )
        session.add(record)
    record.status = status
    record.last_seen_at = utcnow()
    record.last_error = error
    if increment:
        record.processed_count = (record.processed_count or 0) + 1
    session.commit()


def process_one(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    with SessionLocal() as session:
        job = claim_job(session, settings)
        if job is None:
            return False
        try:
            investigation = (
                session.get(Investigation, job.investigation_id) if job.investigation_id else None
            )
            if investigation is None:
                raise RuntimeError("Job has no investigation record.")
            run_pipeline(session, investigation, settings)
            complete_job(session, job)
            _heartbeat(session, settings, status="idle", increment=True)
            return True
        except Exception as exc:  # noqa: BLE001 - job boundary must capture everything
            logger.warning("job %s failed: %s", job.id, safe_error(exc, 200))
            session.rollback()
            fail_job(session, job, exc, settings)
            _heartbeat(session, settings, status="error", error=safe_error(exc, 200))
            return False


def recover(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    with SessionLocal() as session:
        count = recover_expired_leases(session, settings)
        _heartbeat(session, settings, status="idle")
        return count


async def worker_loop(stop_event: asyncio.Event, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    with SessionLocal() as session:
        _heartbeat(session, settings, status="starting")
    recover(settings)
    logger.info("worker started (poll=%ss)", settings.worker_poll_seconds)
    while not stop_event.is_set():
        try:
            processed = await asyncio.to_thread(process_one, settings)
        except Exception as exc:  # pragma: no cover - loop safety
            logger.warning("worker loop error: %s", safe_error(exc, 160))
            processed = False
        if not processed:
            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=max(0.2, settings.worker_poll_seconds)
                )
            except asyncio.TimeoutError:
                pass
    with SessionLocal() as session:
        _heartbeat(session, settings, status="stopped")
    logger.info("worker stopped")
