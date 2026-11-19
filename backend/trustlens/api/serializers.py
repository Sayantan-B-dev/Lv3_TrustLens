"""Plain serialisers keep the API contract explicit and stable."""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import CheckResult, Indicator, Investigation, ThreatReport
from ..security.canonical import CANONICAL_VERSION


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def serialize_check(check: CheckResult) -> dict:
    evidence = check.evidence if isinstance(check.evidence, dict) else {}
    return {
        "id": check.id,
        "check_id": check.check_id,
        "category": check.category,
        "status": check.status,
        "severity": check.severity,
        "title": check.title,
        "summary": check.summary,
        "evidence": evidence,
        "findings": evidence.get("findings", []),
        "source": check.source,
        "source_timestamp": check.source_timestamp,
        "limitations": check.limitations or [],
        "impact": check.impact,
        "remediation": check.remediation,
        "duration_ms": check.duration_ms,
    }


def serialize_indicator(indicator: Indicator) -> dict:
    return {
        "type": indicator.type,
        "value": indicator.value,
        "confidence": indicator.confidence,
        "provenance": indicator.provenance,
        "first_seen": iso(indicator.created_at),
    }


def serialize_report(report: ThreatReport, *, include_payload: bool = False) -> dict:
    data = {
        "id": report.id,
        "investigation_id": report.investigation_id,
        "version": report.version,
        "canonical_version": report.canonical_version or CANONICAL_VERSION,
        "digest": report.digest,
        "report_ref": report.report_ref,
        "status": report.status,
        "chain_id": report.chain_id,
        "contract_address": report.contract_address,
        "tx_hash": report.tx_hash,
        "block_number": report.block_number,
        "committed_at": iso(report.committed_at),
        "created_at": iso(report.created_at),
        "last_error": report.last_error,
    }
    if include_payload:
        data["payload"] = report.payload
    return data


def serialize_investigation(
    investigation: Investigation,
    *,
    checks: list[CheckResult] | None = None,
    indicators: list[Indicator] | None = None,
    reports: list[ThreatReport] | None = None,
    include_checks: bool = True,
) -> dict:
    check_list = checks or []
    ai = next((c for c in check_list if c.check_id == "ai.explanation"), None)
    data = {
        "id": investigation.id,
        "input_type": investigation.input_type,
        "display_value": investigation.display_value,
        "mode": investigation.mode,
        "status": investigation.status,
        "risk_classification": investigation.risk_classification,
        "score": investigation.score,
        "confidence": investigation.confidence,
        "coverage": investigation.coverage,
        "ruleset_version": investigation.ruleset_version,
        "summary": investigation.summary,
        "error": investigation.error,
        "checks_total": investigation.checks_total,
        "checks_completed": investigation.checks_completed,
        "checks_requested": investigation.checks_requested or [],
        "ai_provider": investigation.ai_provider,
        "ai_model": investigation.ai_model,
        "ai_used": investigation.ai_used,
        "created_at": iso(investigation.created_at),
        "started_at": iso(investigation.started_at),
        "completed_at": iso(investigation.completed_at),
        "expires_at": iso(investigation.expires_at),
        "ai_explanation": (ai.evidence if ai else None),
        "indicator_count": len(indicators or []),
        "report_count": len(reports or []),
    }
    if include_checks:
        data["checks"] = [serialize_check(check) for check in check_list]
        data["indicators"] = [serialize_indicator(indicator) for indicator in (indicators or [])]
        data["reports"] = [serialize_report(report) for report in (reports or [])]
    return data
