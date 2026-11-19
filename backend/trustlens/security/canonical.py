"""Canonical serialisation for verifiable threat reports.

The scheme is deliberately small and documented: object keys sorted, no
insignificant whitespace, UTF-8 output, NFC-normalised strings, and floats
rounded to four decimals. It is stable across Python versions and easy to
reproduce in another language (the Hardhat verification script does exactly
this for the digest comparison).
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Any

CANONICAL_VERSION = "trustlens.report/v1"


def _normalise(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _normalise(val) for key, val in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("canonical JSON forbids NaN/Infinity")
        rounded = round(value, 4)
        return 0.0 if rounded == 0 else rounded
    return value


def canonical_json(payload: dict) -> str:
    return json.dumps(
        _normalise(payload),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def report_digest(payload: dict) -> str:
    return sha256_hex(canonical_json(payload))


def report_ref_hex(investigation_id: str, version: int) -> str:
    """Deterministic bytes32 report identifier (0x + 64 hex chars)."""
    return "0x" + sha256_hex(f"{CANONICAL_VERSION}:{investigation_id}:v{version}")
