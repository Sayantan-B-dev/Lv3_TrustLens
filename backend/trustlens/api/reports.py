"""Threat-report integrity API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from pymongo.database import Database

from ..config import Settings, get_settings
from ..db import get_db
from ..models import utcnow
from ..security.canonical import report_digest
from ..security.redaction import safe_error
from ..services import chain
from ..services.reports import build_report_payload, create_report
from .deps import Principal, audit, get_principal, owned_investigation
from .serializers import serialize_report

router = APIRouter(prefix="/threat-reports", tags=["threat-reports"])


class CreateReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str


def _owned_report(db: Database, principal: Principal, report_id: str) -> tuple[dict, dict]:
    investigation = db.investigations.find_one({"reports.id": report_id})
    if (
        investigation is None
        or investigation.get("owner_kind") != principal.kind
        or investigation.get("owner_id") != principal.id
    ):
        raise HTTPException(status_code=404, detail="Threat report not found.")
    report = next(
        (item for item in investigation.get("reports") or [] if item.get("id") == report_id),
        None,
    )
    if report is None:  # pragma: no cover - defensive
        raise HTTPException(status_code=404, detail="Threat report not found.")
    return investigation, report


def _update_report(
    db: Database, investigation_id: str, report: dict, updates: dict
) -> None:
    if not updates:
        return
    db.investigations.update_one(
        {"_id": investigation_id, "reports.id": report["id"]},
        {"$set": {f"reports.$.{key}": value for key, value in updates.items()}},
    )
    report.update(updates)


@router.post("", status_code=201)
def create(
    payload: CreateReportIn,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    investigation = owned_investigation(db, principal, payload.investigation_id)
    if investigation.get("status") != "completed" or not investigation.get("risk_classification"):
        raise HTTPException(
            status_code=409,
            detail="Complete the investigation before publishing a report.",
        )
    latest = max(
        investigation.get("reports") or [],
        key=lambda item: item.get("created_at") or utcnow(),
        default=None,
    )
    if latest is not None and latest.get("status") in {"created", "committed", "verified"}:
        # Idempotent: reuse the existing unrevised commitment.
        if latest.get("digest") == report_digest(latest.get("payload") or {}):
            return serialize_report(latest, include_payload=True)

    report = create_report(
        db,
        investigation,
        submitter_kind=principal.kind,
        submitter_id=principal.id,
    )
    audit(
        db,
        principal,
        "threat_report.created",
        target=report["id"],
        detail={"digest": report["digest"], "investigation_id": investigation["_id"]},
    )
    return serialize_report(report, include_payload=True)


@router.get("/{report_id}")
def detail(
    report_id: str,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    _investigation, report = _owned_report(db, principal, report_id)
    return serialize_report(report, include_payload=True)


@router.post("/{report_id}/commit")
def commit(
    report_id: str,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
    settings: Settings = Depends(get_settings),
):
    investigation, report = _owned_report(db, principal, report_id)
    if not settings.chain_configured:
        raise HTTPException(
            status_code=409,
            detail="The blockchain registry is not configured. Deploy it locally and set CHAIN_CONTRACT_ADDRESS.",
        )
    if report.get("status") in {"committed", "verified"} and report.get("tx_hash"):
        return serialize_report(report)
    try:
        result = chain.commit_digest(report["report_ref"], report["digest"], settings)
    except chain.ChainError as exc:
        message = safe_error(exc, 300)
        _update_report(db, investigation["_id"], report, {"last_error": message})
        raise HTTPException(status_code=502, detail=message) from exc

    updates = {
        "tx_hash": result["tx_hash"],
        "block_number": result["block_number"],
        "chain_id": result["chain_id"],
        "contract_address": result["contract_address"],
        "status": "committed",
        "committed_at": utcnow(),
        "last_error": None,
    }
    _update_report(db, investigation["_id"], report, updates)
    audit(
        db,
        principal,
        "threat_report.committed",
        target=report["id"],
        detail={"tx_hash": report["tx_hash"], "chain_id": report["chain_id"]},
    )
    return serialize_report(report)


@router.post("/{report_id}/verify")
def verify(
    report_id: str,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
    settings: Settings = Depends(get_settings),
):
    investigation, report = _owned_report(db, principal, report_id)
    recomputed = report_digest(report.get("payload") or {})
    digest_consistent = recomputed == report.get("digest")
    chain_result = chain.verify_digest(report["report_ref"], report["digest"], settings)
    if chain_result.get("status") == "verified" and digest_consistent:
        _update_report(db, investigation["_id"], report, {"status": "verified"})
    return {
        "report": serialize_report(report),
        "digest_consistent": digest_consistent,
        "recomputed_digest": recomputed,
        "stored_digest": report.get("digest"),
        "chain": chain_result,
        "explanation": (
            "Blockchain verification confirms that the committed report data has not changed. "
            "It does not prove that the report's claims are true."
        ),
        "verified_at": utcnow().isoformat(),
    }
