"""Deterministic cross-investigation IOC correlation.

Only aggregated, privacy-preserving matches are returned: counts and dates.
Another user's raw content is never exposed.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Indicator, Investigation
from ..security.redaction import mask_email, mask_phone


def correlate(session: Session, investigation_id: str, indicators: list[dict]) -> dict:
    if not indicators:
        return {"matches": [], "summary": "No indicators were available to correlate."}

    values = [item["normalized_value"] for item in indicators]
    # Deduplicate and bound the query.
    values = list(dict.fromkeys(values))[:40]

    rows = session.execute(
        select(
            Indicator.normalized_value,
            Indicator.type,
            func.count(func.distinct(Indicator.investigation_id)).label("investigation_count"),
            func.min(Indicator.created_at).label("first_seen"),
            func.max(Indicator.created_at).label("last_seen"),
        )
        .join(Investigation, Investigation.id == Indicator.investigation_id)
        .where(
            Indicator.normalized_value.in_(values),
            Indicator.investigation_id != investigation_id,
            Investigation.status == "completed",
        )
        .group_by(Indicator.normalized_value, Indicator.type)
    ).all()

    matches = []
    for row in rows:
        value = str(row.normalized_value)
        if row.type == "email":
            value = mask_email(value)
        elif row.type == "phone":
            value = mask_phone(value)
        matches.append(
            {
                "type": row.type,
                "value": value[:200],
                "investigations": int(row.investigation_count),
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
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
