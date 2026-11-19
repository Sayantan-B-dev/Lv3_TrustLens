"""Deterministic cross-investigation IOC correlation.

Only aggregated, privacy-preserving matches are returned: counts and dates.
Another user's raw content is never exposed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pymongo.database import Database

from ..security.redaction import mask_email, mask_phone


def _iso(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return value


def correlate(db: Database, investigation_id: str, indicators: list[dict]) -> dict:
    if not indicators:
        return {"matches": [], "summary": "No indicators were available to correlate."}

    values = [item["normalized_value"] for item in indicators if item.get("normalized_value")]
    # Deduplicate and bound the query.
    values = list(dict.fromkeys(values))[:40]
    if not values:
        return {"matches": [], "summary": "No indicators were available to correlate."}
    value_set = set(values)

    rows = (
        db.investigations.find(
            {
                "status": "completed",
                "_id": {"$ne": investigation_id},
                "indicators.normalized_value": {"$in": values},
            },
            {"indicators": 1},
        )
        .limit(500)
    )

    grouped: dict[tuple[str, str], dict] = {}
    for document in rows:
        for indicator in document.get("indicators") or []:
            normalized = indicator.get("normalized_value")
            if not isinstance(normalized, str) or normalized not in value_set:
                continue
            indicator_type = str(indicator.get("type") or "unknown")
            key = (normalized, indicator_type)
            item = grouped.get(key)
            if item is None:
                item = {
                    "value": normalized,
                    "type": indicator_type,
                    "investigations": set(),
                    "first_seen": None,
                    "last_seen": None,
                }
                grouped[key] = item
            item["investigations"].add(document["_id"])
            seen = indicator.get("created_at")
            if isinstance(seen, datetime):
                if item["first_seen"] is None or seen < item["first_seen"]:
                    item["first_seen"] = seen
                if item["last_seen"] is None or seen > item["last_seen"]:
                    item["last_seen"] = seen

    matches = []
    for item in grouped.values():
        value = item["value"]
        if item["type"] == "email":
            value = mask_email(value)
        elif item["type"] == "phone":
            value = mask_phone(value)
        matches.append(
            {
                "type": item["type"],
                "value": value[:200],
                "investigations": len(item["investigations"]),
                "first_seen": _iso(item["first_seen"]),
                "last_seen": _iso(item["last_seen"]),
            }
        )

    matches.sort(key=lambda item: (-item["investigations"], item["type"]))
    matches = matches[:20]

    findings = []
    if matches:
        findings.append(
            {
                "rule_id": "correlation.shared_indicator",
                "severity": "medium",
                "title": "Indicators seen in earlier investigations",
                "summary": f"{len(matches)} indicator(s) have appeared in prior reports.",
                "evidence": {"matches": matches},
                "impact": "Shared infrastructure suggests the current item may belong to a wider campaign.",
                "remediation": "Review related indicators together rather than in isolation.",
                "limitations": [
                    "Shared indicators can be benign (shared hosting, reused links, common brands).",
                    "Matching is exact after normalisation and does not prove a common actor.",
                ],
                "authoritative": False,
            }
        )

    return {
        "matches": matches,
        "findings": findings,
        "summary": (
            f"{len(matches)} indicator(s) also appeared elsewhere in TrustLens."
            if matches
            else "No previously reported indicators matched."
        ),
        "limitations": [
            "Correlation is exact-match over normalised indicators within this deployment.",
            "No external campaign attribution is implied.",
        ],
    }
