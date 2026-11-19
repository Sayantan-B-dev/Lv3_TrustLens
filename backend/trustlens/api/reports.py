"""Threat-report integrity API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db import get_db
from ..models import ThreatReport, utcnow
from ..security.canonical import report_digest
from ..security.redaction import safe_error
from ..services import chain
from .deps import Principal, audit, get_principal, owned_investigation
from .serializers import serialize_report

router = APIRouter(prefix="/threat-reports", tags=["threat-reports"])


class CreateReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str


def _owned_report(db: Session, principal: Principal, report_id: str) -> ThreatReport:
    report = db.get(ThreatReport, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Threat report not found.")
    investigation = report.investigation
    if (
        investigation is None
        or investigation.owner_kind != principal.kind
        or investigation.owner_id != principal.id
    ):
        raise HTTPException(status_code=404, detail="Threat report not found.")
    return report


@router.post("", status_code=201)
def create(
    payload: CreateReportIn,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    investigation = owned_investigation(db, principal, payload.investigation_id)
    if investigation.status != "completed" or not investigation.risk_classification:
        raise HTTPException(
            status_code=409,
            detail="Complete the investigation before publishing a report.",
        )
    latest = db.execute(
        select(ThreatReport)
        .where(ThreatReport.investigation_id == investigation.id)
        .order_by(ThreatReport.created_at.desc())
    ).scalars().first()
    if latest is not None and latest.status in {"created", "committed", "verified"}:
        # Idempotent: reuse the existing unrevised commitment.
        if serialize_report(latest)["digest"] == report_digest(latest.payload):
            return serialize_report(latest, include_payload=True)
    from ..services.reports import create_report

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
        target=report.id,
        detail={"digest": report.digest, "investigation_id": investigation.id},
    )
    return serialize_report(report, include_payload=True)


@router.get("/{report_id}")
def detail(
    report_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    report = _owned_report(db, principal, report_id)
    return serialize_report(report, include_payload=True)


@router.post("/{report_id}/commit")
def commit(
    report_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
    settings: Settings = Depends(get_settings),
):
    report = _owned_report(db, principal, report_id)
    if not settings.chain_configured:
        raise HTTPException(
            status_code=409,
            detail="The blockchain registry is not configured. Deploy it locally and set CHAIN_CONTRACT_ADDRESS.",
        )
    if report.status in {"committed", "verified"} and report.tx_hash:
        return serialize_report(report)
    try:
        result = chain.commit_digest(report.report_ref, report.digest, settings)
    except chain.ChainError as exc:
        report.last_error = safe_error(exc, 300)
        db.commit()
        raise HTTPException(status_code=502, detail=report.last_error) from exc

    report.tx_hash = result["tx_hash"]
    report.block_number = result["block_number"]
    report.chain_id = result["chain_id"]
    report.contract_address = result["contract_address"]
    report.status = "committed"
    report.committed_at = utcnow()
    report.last_error = None
    db.commit()
    audit(
        db,
        principal,
        "threat_report.committed",
        target=report.id,
        detail={"tx_hash": report.tx_hash, "chain_id": report.chain_id},
    )
    return serialize_report(report)


@router.post("/{report_id}/verify")
def verify(
    report_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
    settings: Settings = Depends(get_settings),
):
    report = _owned_report(db, principal, report_id)
    recomputed = report_digest(report.payload)
    digest_consistent = recomputed == report.digest
    chain_result = chain.verify_digest(report.report_ref, report.digest, settings)
    if chain_result.get("status") == "verified" and digest_consistent:
        report.status = "verified"
        db.commit()
    return {
        "report": serialize_report(report),
        "digest_consistent": digest_consistent,
        "recomputed_digest": recomputed,
        "stored_digest": report.digest,
        "chain": chain_result,
        "explanation": (
            "Blockchain verification confirms that the committed report data has not changed. "
            "It does not prove that the report's claims are true."
        ),
        "verified_at": utcnow().isoformat(),
    }
