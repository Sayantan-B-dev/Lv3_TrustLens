"""Redaction helpers used before logging, AI calls and report publication."""

from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"(\+?\d[\d\s\-()]{6,}\d)")
_SECRET_KEY_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|otp|pin|cvv|secret|api[_-]?key|token|seed(?: phrase)?|private[_-]?key)\b\s*[:=]\s*\S+"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_LONG_DIGITS_RE = re.compile(r"\b\d{6,}\b")
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)


def mask_email(value: str) -> str:
    match = _EMAIL_RE.search(value)
    if match:
        return f"{match.group(1)}***{match.group(2)}"
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    return value


def mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 4:
        return "***"
    return f"***{digits[-4:]}"


def redact_text(text: str) -> str:
    """Best-effort redaction. Not a substitute for never collecting secrets."""
    text = _PRIVATE_KEY_BLOCK_RE.sub("[redacted private key]", text)
    text = _JWT_RE.sub("[redacted token]", text)
    text = _SECRET_KEY_RE.sub(lambda m: f"{m.group(1)}=[redacted]", text)
    text = _EMAIL_RE.sub(lambda m: f"{m.group(1)}***{m.group(2)}", text)
    text = _LONG_DIGITS_RE.sub("[redacted number]", text)
    return text


def safe_error(exc: BaseException, limit: int = 240) -> str:
    message = redact_text(str(exc))
    message = re.sub(r"\s+", " ", message).strip()
    return message[:limit] or exc.__class__.__name__


def sanitize_for_log(value: object, limit: int = 500) -> str:
    return redact_text(str(value))[:limit]
