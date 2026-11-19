"""System status exposed to the dashboard (no secrets)."""

from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends
from pymongo.database import Database

from ..config import Settings, get_settings
from ..db import get_db
from ..intelligence.pipeline import CHECK_CATALOG, DEFAULT_CHECKS
from ..intelligence.risk import RISK_CLASSES, RISK_DEFINITIONS
from ..models import utcnow
from ..services.jobs import queue_depth

router = APIRouter(tags=["system"])


@router.get("/system/status")
def status(
    db: Database = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    heartbeat = db.worker_heartbeats.find_one({"_id": settings.worker_name})
    heartbeat_age = None
    worker_online = False
    if heartbeat is not None and heartbeat.get("last_seen_at") is not None:
        last_seen = heartbeat["last_seen_at"]
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        heartbeat_age = int((utcnow() - last_seen).total_seconds())
        worker_online = heartbeat_age <= max(45, int(settings.worker_poll_seconds * 4))

    rule = db.rule_versions.find_one({"_id": "trustlens-rules-v1"})
    return {
        "app": settings.app_name,
        "environment": settings.environment,
        "database": "mongodb",
        "worker": {
            "enabled": settings.worker_enabled,
            "online": worker_online,
            "status": heartbeat.get("status") if heartbeat else "not_started",
            "last_seen_seconds_ago": heartbeat_age,
            "processed_count": heartbeat.get("processed_count", 0) if heartbeat else 0,
        },
        "queue": queue_depth(db),
        "providers": {
            "urlhaus": {"enabled": settings.threat_intel_enabled, "key_configured": bool(settings.urlhaus_auth_key)},
            "crt_sh": {"enabled": settings.ct_lookup_enabled},
            "ai": {
                "mode": settings.active_ai_provider,
                "model": settings.ai_model if settings.active_ai_provider == "openai" else "rules-only",
                "configured": bool(settings.ai_api_key),
            },
            "oauth_google": {"configured": settings.oauth_configured},
            "chain": {
                "configured": settings.chain_configured,
                "chain_id": settings.chain_id,
                "contract_address": settings.chain_contract_address or None,
                "signer_configured": bool(settings.chain_private_key),
                "explorer_base": settings.chain_explorer_base or None,
            },
        },
        "ruleset": {
            "version": rule["_id"] if rule else "trustlens-rules-v1",
            "active": bool(rule.get("active", True)) if rule else True,
        },
        "limits": {
            "max_input_chars": settings.max_input_chars,
            "anonymous_retention_days": settings.anonymous_retention_days,
            "user_retention_days": settings.user_retention_days,
        },
    }


@router.get("/meta")
def meta():
    return {
        "product": "TrustLens",
        "objective": "Evidence-first web threat detection and digital trust intelligence.",
        "risk_classes": [
            {"name": name, "definition": RISK_DEFINITIONS[name]} for name in RISK_CLASSES
        ],
        "checks": CHECK_CATALOG,
        "defaults": {"url": DEFAULT_CHECKS, "message": DEFAULT_CHECKS},
        "privacy": (
            "Submitted links and messages are stored for the configured retention period. "
            "Raw message bodies are never placed on-chain and are redacted before AI processing. "
            "Do not paste passwords, OTPs, private keys or seed phrases."
        ),
        "limitations": [
            "Passive checks only; no exploitation or active scanning.",
            "No match in a threat feed is not proof of safety.",
            "TLS validity proves encryption and certificate identity, not honest intent.",
            "Blockchain records prove report integrity, not the truth of the report.",
        ],
    }


@router.get("/debug/db")
def debug_db(db: Database = Depends(get_db)):  # intentionally minimal; no secrets
    db.command("ping")
    return {"database": "mongodb", "ok": True}
