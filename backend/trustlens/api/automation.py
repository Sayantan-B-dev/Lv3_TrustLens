"""Automation settings API (persisted per owner)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from ..db import get_db
from ..intelligence.pipeline import CHECK_CATALOG, DEFAULT_CHECKS
from ..models import new_automation, utcnow
from .deps import Principal, audit, get_principal

router = APIRouter(prefix="/automation", tags=["automation"])


class AutomationPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["automatic", "manual"] | None = None
    paused: bool | None = None
    modules: dict[str, bool] | None = None


def get_or_create(db: Database, principal: Principal) -> dict:
    key = f"{principal.kind}:{principal.id}"
    setting = db.automation_settings.find_one({"_id": key})
    if setting is None:
        setting = new_automation(
            owner_key=key,
            modules={check: True for check in DEFAULT_CHECKS},
        )
        try:
            db.automation_settings.insert_one(setting)
        except DuplicateKeyError:
            setting = db.automation_settings.find_one({"_id": key})
    return setting or new_automation(
        owner_key=key, modules={check: True for check in DEFAULT_CHECKS}
    )


def serialize(setting: dict) -> dict:
    modules = setting.get("modules") or {}
    updated_at = setting.get("updated_at")
    return {
        "mode": setting.get("mode", "automatic"),
        "paused": bool(setting.get("paused", False)),
        "modules": {check: bool(modules.get(check, True)) for check in CHECK_CATALOG},
        "updated_at": updated_at.isoformat() if updated_at else None,
        "note": "Automatic mode runs safe passive checks only. It never performs active scanning.",
    }


@router.get("")
def read(
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    return serialize(get_or_create(db, principal))


@router.patch("")
def update(
    payload: AutomationPatch,
    db: Database = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    setting = get_or_create(db, principal)
    updates: dict = {"updated_at": utcnow()}
    if payload.mode is not None:
        updates["mode"] = payload.mode
    if payload.paused is not None:
        updates["paused"] = payload.paused
    if payload.modules is not None:
        unknown = [key for key in payload.modules if key not in CHECK_CATALOG]
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown module(s): {', '.join(unknown[:5])}")
        merged = dict(setting.get("modules") or {})
        merged.update({key: bool(value) for key, value in payload.modules.items()})
        updates["modules"] = merged
    db.automation_settings.update_one({"_id": setting["_id"]}, {"$set": updates})
    setting = db.automation_settings.find_one({"_id": setting["_id"]}) or setting
    audit(
        db,
        principal,
        "automation.updated",
        detail={"mode": setting.get("mode"), "paused": setting.get("paused")},
    )
    return serialize(setting)
