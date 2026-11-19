"""Report construction and integrity services."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..intelligence.risk import RISK_DEFINITIONS
from ..models import CheckResult, Indicator, Investigation, ThreatReport
from ..security.canonical import CANONICAL_VERSION, report_digest, report_ref_hex, sha256_hex
from ..security.redaction import mask_email, mask_phone


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def build_report_payload(
    session: Session,
    investigation: Investigation,
    *,
    version: int = 1,
) -> dict:
    checks = (
        session.query(CheckResult)
        .filter(CheckResult.investigation_id == investigation.id)
        .order_by(CheckResult.id)
        .all()
    )
    indicators = (
        session.query(Indicator)
        .filter(Indicator.investigation_id == investigation.id)
        .order_by(Indicator.id)
        .all()
    )

    findings = []
    for check in checks:
        if check.check_id in {"risk.assessment", "ai.explanation"}:
            continue
        findings.append(
            {
                "check_id": check.check_id,
                "category": check.category,
                "status": check.status,
                "severity": check.severity,
                "title": check.title,
                "summary": (check.summary or "")[:400],
            }
        )

    indicator_payload = []
    for indicator in indicators:
        value = indicator.value
        if indicator.type == "email":
            value = mask_email(value)
        elif indicator.type == "phone":
            value = mask_phone(value)
        indicator_payload.append(
            {
                "type": indicator.type,
                "value": value[:200],
                "digest": sha256_hex(indicator.normalized_value)[:32],
                "confidence": round(indicator.confidence, 2),
            }
        )

    return {
        "schema": CANONICAL_VERSION,
        "report_version": version,
        "investigation_id": investigation.id,
        "input_type": investigation.input_type,
        "target": investigation.display_value,
        "risk_classification": investigation.risk_classification,
        "risk_definition": RISK_DEFINITIONS.get(
            investigation.risk_classification or "Inconclusive", ""
        ),
        "score": investigation.score,
        "confidence": investigation.confidence,
        "coverage": investigation.coverage,
        "ruleset_version": investigation.ruleset_version,
        "checks": findings,
        "indicators": indicator_payload,
        "created_at": _iso(investigation.created_at),
        "completed_at": _iso(investigation.completed_at),
        "limitations": "TrustLens performs passive checks only. Report integrity does not prove that the findings are true.",
    }


def create_report(
    session: Session,
    investigation: Investigation,
    *,
    submitter_kind: str,
    submitter_id: str,
) -> ThreatReport:
    version = (
        session.query(ThreatReport)
        .filter(ThreatReport.investigation_id == investigation.id)
        .count()
        + 1
    )
    payload = build_report_payload(session, investigation, version=version)
    digest = report_digest(payload)
    report = ThreatReport(
        investigation_id=investigation.id,
        submitter_kind=submitter_kind,
        submitter_id=submitter_id,
        version=version,
        canonical_version=CANONICAL_VERSION,
        payload=payload,
        digest=digest,
        report_ref=report_ref_hex(investigation.id, version),
        status="created",
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return report
