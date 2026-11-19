"""Report construction and integrity services."""

from __future__ import annotations

from datetime import datetime, timezone

from pymongo import ReturnDocument
from pymongo.database import Database

from ..intelligence.risk import RISK_DEFINITIONS
from ..models import new_report
from ..security.canonical import CANONICAL_VERSION, report_digest, report_ref_hex, sha256_hex
from ..security.redaction import mask_email, mask_phone


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def build_report_payload(
    investigation: dict,
    *,
    version: int = 1,
) -> dict:
    checks = sorted(
        investigation.get("checks") or [],
        key=lambda item: item.get("id", 0),
    )
    indicators = list(investigation.get("indicators") or [])

    findings = []
    for check in checks:
        if check.get("check_id") in {"risk.assessment", "ai.explanation"}:
            continue
        findings.append(
            {
                "check_id": check.get("check_id"),
                "category": check.get("category"),
                "status": check.get("status"),
                "severity": check.get("severity"),
                "title": check.get("title"),
                "summary": (check.get("summary") or "")[:400],
            }
        )

    indicator_payload = []
    for indicator in indicators:
        value = indicator.get("value") or ""
        if indicator.get("type") == "email":
            value = mask_email(value)
        elif indicator.get("type") == "phone":
            value = mask_phone(value)
        indicator_payload.append(
            {
                "type": indicator.get("type"),
                "value": value[:200],
                "digest": sha256_hex(indicator.get("normalized_value") or "")[:32],
                "confidence": round(indicator.get("confidence") or 0.0, 2),
            }
        )

    return {
        "schema": CANONICAL_VERSION,
        "report_version": version,
        "investigation_id": investigation.get("_id"),
        "input_type": investigation.get("input_type"),
        "target": investigation.get("display_value"),
        "risk_classification": investigation.get("risk_classification"),
        "risk_definition": RISK_DEFINITIONS.get(
            investigation.get("risk_classification") or "Inconclusive", ""
        ),
        "score": investigation.get("score", 0),
        "confidence": investigation.get("confidence"),
        "coverage": investigation.get("coverage"),
        "ruleset_version": investigation.get("ruleset_version"),
        "checks": findings,
        "indicators": indicator_payload,
        "created_at": _iso(investigation.get("created_at")),
        "completed_at": _iso(investigation.get("completed_at")),
        "limitations": "TrustLens performs passive checks only. Report integrity does not prove that the findings are true.",
    }


def create_report(
    db: Database,
    investigation: dict,
    *,
    submitter_kind: str,
    submitter_id: str,
) -> dict:
    sequence = db.investigations.find_one_and_update(
        {"_id": investigation["_id"]},
        {"$inc": {"report_seq": 1}},
        projection={"report_seq": 1},
        return_document=ReturnDocument.AFTER,
    )
    if sequence is None:  # pragma: no cover - investigation was deleted concurrently
        raise RuntimeError("Investigation no longer exists.")
    version = int(sequence.get("report_seq") or 1)
    payload = build_report_payload(investigation, version=version)
    report = new_report(
        investigation_id=investigation["_id"],
        submitter_kind=submitter_kind,
        submitter_id=submitter_id,
        version=version,
        canonical_version=CANONICAL_VERSION,
        payload=payload,
        digest=report_digest(payload),
        report_ref=report_ref_hex(investigation["_id"], version),
    )
    db.investigations.update_one(
        {"_id": investigation["_id"]},
        {"$push": {"reports": report}},
    )
    return report
