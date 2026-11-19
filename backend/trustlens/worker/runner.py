"""Embedded worker loop.

One Render service runs the API and this loop. Work is claimed from MongoDB
with leases, so a crash or restart does not lose queued work.
"""

from __future__ import annotations

import asyncio
import logging

from pymongo.database import Database

from ..config import Settings, get_settings
from ..db import database
from ..models import utcnow
from ..security.redaction import safe_error
from ..services.jobs import claim_job, complete_job, fail_job, recover_expired_leases
from ..intelligence.pipeline import run_pipeline

logger = logging.getLogger("trustlens.worker")


def _heartbeat(
    db: Database,
    settings: Settings,
    *,
    status: str,
    error: str | None = None,
    increment: bool = False,
) -> None:
    now = utcnow()
    update: dict = {
        "$set": {
            "status": status,
            "last_seen_at": now,
            "last_error": error,
        },
        "$setOnInsert": {"started_at": now},
    }
    if increment:
        update["$inc"] = {"processed_count": 1}
    db.worker_heartbeats.update_one({"_id": settings.worker_name}, update, upsert=True)


def process_one(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    job = claim_job(database, settings)
    if job is None:
        return False
    try:
        investigation = (
            database.investigations.find_one({"_id": job["investigation_id"]})
            if job.get("investigation_id")
            else None
        )
        if investigation is None:
            raise RuntimeError("Job has no investigation record.")
        run_pipeline(database, investigation, settings)
        complete_job(database, job)
        try:
            _heartbeat(database, settings, status="idle", increment=True)
        except Exception as exc:  # heartbeat must never requeue a finished job
            logger.warning("heartbeat failed: %s", safe_error(exc, 160))
        return True
    except Exception as exc:  # noqa: BLE001 - job boundary must capture everything
        logger.warning("job %s failed: %s", job.get("_id"), safe_error(exc, 200))
        fail_job(database, job, exc, settings)
        _heartbeat(database, settings, status="error", error=safe_error(exc, 200))
        return False


def recover(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    count = recover_expired_leases(database, settings)
    _heartbeat(database, settings, status="idle")
    return count


async def worker_loop(stop_event: asyncio.Event, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    _heartbeat(database, settings, status="starting")
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
    _heartbeat(database, settings, status="stopped")
    logger.info("worker stopped")
