"""Signed cookie payloads (HMAC-SHA256, no third-party session library)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from ..config import get_settings


def _secret() -> bytes:
    return get_settings().session_secret.encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def sign_payload(payload: dict) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(_secret(), body, hashlib.sha256).digest()
    return f"{_b64(body)}.{_b64(signature)}"


def unsign_payload(token: str | None, max_age_seconds: int | None = None) -> dict | None:
    if not token or "." not in token:
        return None
    body_part, sig_part = token.split(".", 1)
    try:
        body = _unb64(body_part)
        signature = _unb64(sig_part)
    except (ValueError, TypeError):
        return None
    expected = hmac.new(_secret(), body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    issued = payload.get("iat")
    if max_age_seconds is not None:
        if not isinstance(issued, (int, float)) or time.time() - issued > max_age_seconds:
            return None
    return payload


def signing_hash(token: str | None) -> str:
    """Store only a digest of cookies in audit records, never the cookie."""
    if not token:
        return ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]
