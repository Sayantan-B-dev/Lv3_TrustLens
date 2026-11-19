"""Plain serialisers keep the API contract explicit and stable."""

from __future__ import annotations

from datetime import datetime, timezone

from ..security.canonical import CANONICAL_VERSION


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def serialize_check(check: dict) -> dict:
    evidence = check.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    return {
        "id": check.get("id"),
        "check_id": check.get("check_id"),
        "category": check.get("category"),
        "status": check.get("status"),
        "severity": check.get("severity"),
        "title": check.get("title"),
        "summary": check.get("summary"),
        "evidence": evidence,
        "findings": evidence.get("findings", []),
        "source": check.get("source"),
        "source_timestamp": check.get("source_timestamp"),
        "limitations": check.get("limitations") or [],
        "impact": check.get("impact"),
        "remediation": check.get("remediation"),
        "duration_ms": check.get("duration_ms", 0),
    }


def serialize_indicator(indicator: dict) -> dict:
    return {
        "type": indicator.get("type"),
        "value": indicator.get("value"),
        "confidence": indicator.get("confidence"),
        "provenance": indicator.get("provenance"),
        "first_seen": iso(indicator.get("created_at")),
    }


def serialize_report(report: dict, *, include_payload: bool = False) -> dict:
    data = {
        "id": report.get("id"),
        "investigation_id": report.get("investigation_id"),
        "version": report.get("version", 1),
        "canonical_version": report.get("canonical_version") or CANONICAL_VERSION,
        "digest": report.get("digest"),
        "report_ref": report.get("report_ref"),
        "status": report.get("status"),
        "chain_id": report.get("chain_id"),
        "contract_address": report.get("contract_address"),
        "tx_hash": report.get("tx_hash"),
        "block_number": report.get("block_number"),
        "committed_at": iso(report.get("committed_at")),
        "created_at": iso(report.get("created_at")),
        "last_error": report.get("last_error"),
    }
    if include_payload:
        data["payload"] = report.get("payload")
    return data


def serialize_investigation(
    investigation: dict,
    *,
    checks: list[dict] | None = None,
    indicators: list[dict] | None = None,
    reports: list[dict] | None = None,
    include_checks: bool = True,
) -> dict:
    check_list = checks or []
    ai = next((c for c in check_list if c.get("check_id") == "ai.explanation"), None)
    data = {
        "id": investigation.get("_id"),
        "input_type": investigation.get("input_type"),
        "display_value": investigation.get("display_value"),
        "mode": investigation.get("mode"),
        "status": investigation.get("status"),
        "risk_classification": investigation.get("risk_classification"),
        "score": investigation.get("score", 0),
        "confidence": investigation.get("confidence"),
        "coverage": investigation.get("coverage"),
        "ruleset_version": investigation.get("ruleset_version"),
        "summary": investigation.get("summary"),
        "error": investigation.get("error"),
        "checks_total": investigation.get("checks_total", 0),
        "checks_completed": investigation.get("checks_completed", 0),
        "checks_requested": investigation.get("checks_requested") or [],
        "ai_provider": investigation.get("ai_provider"),
        "ai_model": investigation.get("ai_model"),
        "ai_used": investigation.get("ai_used", False),
        "created_at": iso(investigation.get("created_at")),
        "started_at": iso(investigation.get("started_at")),
        "completed_at": iso(investigation.get("completed_at")),
        "expires_at": iso(investigation.get("expires_at")),
        "ai_explanation": (ai.get("evidence") if ai else None),
        "indicator_count": len(indicators or []),
        "report_count": len(reports or []),
    }
    if include_checks:
        data["checks"] = [serialize_check(check) for check in check_list]
        data["indicators"] = [serialize_indicator(indicator) for indicator in (indicators or [])]
        data["reports"] = [serialize_report(report) for report in (reports or [])]
    return data
