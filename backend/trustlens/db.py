"""MongoDB connection, collections and index bootstrap.

``MONGODB_URL`` is the only connection setting required. ``MONGODB_DB`` keeps
TrustLens in a dedicated database even when the cluster is shared. Local
development uses ``mongodb://127.0.0.1:27017``; tests may use the
``mongomock://`` scheme.
"""

from __future__ import annotations

from collections.abc import Iterator

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.database import Database

from .config import get_settings


def build_client(url: str) -> MongoClient:
    if url.startswith("mongomock://"):
        import mongomock

        return mongomock.MongoClient(tz_aware=True)  # type: ignore[return-value]

    settings = get_settings()
    return MongoClient(
        url,
        tz_aware=True,
        serverSelectionTimeoutMS=settings.mongodb_timeout_ms,
        connectTimeoutMS=settings.mongodb_timeout_ms,
        maxPoolSize=20,
        retryWrites=True,
    )


settings = get_settings()
client = build_client(settings.mongodb_url)
database: Database = client[settings.mongodb_db]


def get_db() -> Iterator[Database]:
    yield database


def init_db() -> None:
    """Create indexes and seed the deterministic ruleset registry."""
    from .intelligence.risk import RULESET_VERSION
    from .models import utcnow

    database.users.create_index(
        [("provider", ASCENDING), ("subject", ASCENDING)],
        unique=True,
        name="uq_users_provider_subject",
    )
    database.sessions.create_index(
        [("expires_at", ASCENDING)],
        name="ix_sessions_expires",
        expireAfterSeconds=0,
    )
    database.investigations.create_index(
        [("owner_kind", ASCENDING), ("owner_id", ASCENDING), ("created_at", DESCENDING)],
        name="ix_investigations_owner_created",
    )
    database.investigations.create_index(
        [("status", ASCENDING)], name="ix_investigations_status"
    )
    database.investigations.create_index(
        [("indicators.normalized_value", ASCENDING)],
        name="ix_investigations_indicator",
    )
    database.investigations.create_index(
        [("reports.id", ASCENDING)], name="ix_investigations_report"
    )
    database.jobs.create_index(
        [("idempotency_key", ASCENDING)], unique=True, name="uq_jobs_idempotency"
    )
    database.jobs.create_index(
        [("status", ASCENDING), ("available_at", ASCENDING), ("created_at", ASCENDING)],
        name="ix_jobs_queue",
    )
    database.feedback.create_index(
        [("investigation_id", ASCENDING)], name="ix_feedback_investigation"
    )
    database.audit_events.create_index(
        [("created_at", DESCENDING)], name="ix_audit_created"
    )
    database.rule_versions.update_one(
        {"_id": RULESET_VERSION},
        {
            "$setOnInsert": {
                "description": (
                    "Deterministic baseline rules for URL, TLS, header, message and IOC evidence."
                ),
                "active": True,
                "created_at": utcnow(),
            }
        },
        upsert=True,
    )


def reset_database() -> None:
    """Drop the configured database (tests only)."""
    client.drop_database(settings.mongodb_db)


def close_client() -> None:
    client.close()
