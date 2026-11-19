"""Automation settings API (persisted per owner)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..intelligence.pipeline import CHECK_CATALOG, DEFAULT_CHECKS
from ..models import AutomationSetting
from .deps import Principal, audit, get_principal

router = APIRouter(prefix="/automation", tags=["automation"])


class AutomationPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["automatic", "manual"] | None = None
    paused: bool | None = None
    modules: dict[str, bool] | None = None


def get_or_create(db: Session, principal: Principal) -> AutomationSetting:
    key = f"{principal.kind}:{principal.id}"
    setting = db.execute(
        select(AutomationSetting).where(AutomationSetting.owner_key == key)
    ).scalar_one_or_none()
    if setting is None:
        setting = AutomationSetting(
            owner_key=key,
            mode="automatic",
            paused=False,
            modules={check: True for check in DEFAULT_CHECKS},
        )
        db.add(setting)
        db.commit()
        db.refresh(setting)
    return setting


def serialize(setting: AutomationSetting) -> dict:
    modules = {check: bool(setting.modules.get(check, True)) for check in CHECK_CATALOG}
    return {
        "mode": setting.mode,
        "paused": setting.paused,
        "modules": modules,
        "updated_at": setting.updated_at.isoformat() if setting.updated_at else None,
        "note": "Automatic mode runs safe passive checks only. It never performs active scanning.",
    }


@router.get("")
def read(
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    return serialize(get_or_create(db, principal))


@router.patch("")
def update(
    payload: AutomationPatch,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_principal),
):
    setting = get_or_create(db, principal)
    if payload.mode is not None:
        setting.mode = payload.mode
    if payload.paused is not None:
        setting.paused = payload.paused
    if payload.modules is not None:
        unknown = [key for key in payload.modules if key not in CHECK_CATALOG]
        if unknown:
            raise HTTPException(status_code=422, detail=f"Unknown module(s): {', '.join(unknown[:5])}")
        merged = dict(setting.modules or {})
        merged.update({key: bool(value) for key, value in payload.modules.items()})
        setting.modules = merged
    db.commit()
    db.refresh(setting)
    audit(
        db,
        principal,
        "automation.updated",
        detail={"mode": setting.mode, "paused": setting.paused},
    )
    return serialize(setting)
