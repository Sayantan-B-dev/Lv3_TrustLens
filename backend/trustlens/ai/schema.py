"""Strict schema for AI output. Anything else is rejected."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EvidenceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str = Field(min_length=3, max_length=400)
    evidence_ids: list[str] = Field(min_length=1, max_length=6)


class AIExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=3, max_length=900)
    why: list[EvidenceClaim] = Field(min_length=1, max_length=6)
    next_steps: list[str] = Field(min_length=1, max_length=6)
    limitations: list[str] = Field(default_factory=list, max_length=6)
    confidence_note: str = Field(default="", max_length=400)


class AIValidationError(ValueError):
    pass
