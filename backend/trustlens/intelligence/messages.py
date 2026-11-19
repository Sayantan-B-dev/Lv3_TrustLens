"""Deterministic scam-message analysis and IOC extraction.

Language heuristics identify patterns worth investigating. They never label a
message fraudulent on their own: the risk engine requires corroborating
signals, and AI is never allowed to raise or lower the final classification.
"""

from __future__ import annotations

import re

from ..security.redaction import mask_email, mask_phone, redact_text
from .normalize import extract_urls

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<![\w+])(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?){2,4}\d{2,4}(?![\w])")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CRYPTO_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_CRYPTO_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_HANDLE_RE = re.compile(r"(?<!\w)@[A-Za-z0-9_]{3,32}\b")

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _excerpt(text: str, terms: list[str], radius: int = 60) -> str:
    lowered = text.lower()
    for term in terms:
        index = lowered.find(term.lower())
        if index >= 0:
            start = max(0, index - radius)
            end = min(len(text), index + len(term) + radius)
            return redact_text(text[start:end].replace("\n", " "))
    return redact_text(text[:140])


def analyse_message(text: str) -> dict:
    text = text.strip()
    lowered = text.lower()
    indicators: list[dict] = []
    findings: list[dict] = []

    urls = extract_urls(text)
    emails = list(dict.fromkeys(_EMAIL_RE.findall(text)))
    phones = list(dict.fromkeys(match.group(0).strip() for match in _PHONE_RE.finditer(text)))
    ips = [ip for ip in dict.fromkeys(_IPV4_RE.findall(text)) if all(int(part) <= 255 for part in ip.split("."))]
    btc = list(dict.fromkeys(_CRYPTO_BTC_RE.findall(text)))
    eth = list(dict.fromkeys(_CRYPTO_ETH_RE.findall(text)))
    handles = list(dict.fromkeys(_HANDLE_RE.findall(text)))[:10]

    for url in urls[:10]:
        indicators.append({"type": "url", "value": url, "confidence": 0.9, "provenance": "message-extraction"})
    for email in emails[:10]:
        indicators.append({"type": "email", "value": email, "confidence": 0.9, "provenance": "message-extraction"})
    for phone in phones[:10]:
        if len(re.sub(r"\D", "", phone)) >= 8:
            indicators.append({"type": "phone", "value": phone, "confidence": 0.7, "provenance": "message-extraction"})
    for ip in ips[:10]:
        indicators.append({"type": "ip", "value": ip, "confidence": 0.6, "provenance": "message-extraction"})
    for wallet in (btc + eth)[:5]:
        indicators.append({"type": "crypto_wallet", "value": wallet, "confidence": 0.9, "provenance": "message-extraction"})
    for handle in handles[:5]:
        indicators.append({"type": "handle", "value": handle, "confidence": 0.5, "provenance": "message-extraction"})

    categories = {
        "credential_request": {
            "terms": ["otp", "one-time password", "password", "passcode", "pin", "cvv", "seed phrase", "private key", "security code", "verify your account", "confirm your identity"],
            "severity": "high",
            "title": "Request for credentials or verification secrets",
            "impact": "Credentials or one-time codes can be used for account takeover or unauthorised payments.",
            "remediation": "Never share OTPs, passwords, PINs or recovery phrases. Contact the organisation using an official number.",
            "rule": "message.credential_request",
        },
        "payment_request": {
            "terms": ["gift card", "bitcoin", "usdt", "crypto", "wire transfer", "western union", "processing fee", "pay now", "upi", "payment link", "bank transfer"],
            "severity": "high",
            "title": "Unusual payment request",
            "impact": "Irreversible transfers can be lost immediately and are difficult to recover.",
            "remediation": "Verify the request independently. Never pay with gift cards or crypto for unsolicited demands.",
            "rule": "message.payment_request",
        },
        "urgency": {
            "terms": ["urgent", "immediately", "within 24 hours", "final warning", "account suspended", "act now", "last chance", "expires today", "locked"],
            "severity": "low",
            "title": "Pressure and urgency language",
            "impact": "Urgency is used to prevent careful verification.",
            "remediation": "Slow down and verify the sender through a channel you already trust.",
            "rule": "message.urgency",
        },
        "impersonation": {
            "terms": ["official", "security team", "support team", "customer care", "bank", "university", "government", "tax department", "parcel", "delivery", "refund", "kyc"],
            "severity": "medium",
            "title": "Possible authority impersonation",
            "impact": "Attackers pose as trusted institutions to make requests appear legitimate.",
            "remediation": "Check the sender address and contact the institution using its published details.",
            "rule": "message.impersonation",
        },
        "remote_access": {
            "terms": ["anydesk", "teamviewer", "quick support", "remote access", "screen sharing", "install this app"],
            "severity": "high",
            "title": "Remote-access software requested",
            "impact": "Remote-control tools give an attacker direct control of the device and banking sessions.",
            "remediation": "Do not install remote-access software at the request of an unsolicited caller or message.",
            "rule": "message.remote_access",
        },
        "job_scam": {
            "terms": ["work from home", "earn per day", "no experience needed", "investment guaranteed", "double your", "part-time job", "registration fee", "training fee"],
            "severity": "medium",
            "title": "Employment or investment pitch patterns",
            "impact": "Advance-fee job and investment scams extract registration or training payments.",
            "remediation": "Research the employer independently; legitimate employers do not charge candidates.",
            "rule": "message.job_scam",
        },
        "secrecy": {
            "terms": ["do not tell", "keep this confidential", "between us", "don't inform", "do not contact"],
            "severity": "low",
            "title": "Request for secrecy",
            "impact": "Isolation from friends, family or colleagues is a classic social-engineering tactic.",
            "remediation": "Discuss the request with someone you trust before acting.",
            "rule": "message.secrecy",
        },
        "pii_request": {
            "terms": ["aadhaar", "social security", "ssn", "passport number", "date of birth", "mother's maiden", "full card number"],
            "severity": "medium",
            "title": "Sensitive personal data requested",
            "impact": "Identity data enables account takeover and identity fraud.",
            "remediation": "Share identity documents only through verified official channels.",
            "rule": "message.pii_request",
        },
    }

    matched_terms: dict[str, list[str]] = {}
    for key, spec in categories.items():
        hits = [term for term in spec["terms"] if term in lowered]
        if hits:
            matched_terms[key] = hits
            findings.append(
                {
                    "rule_id": spec["rule"],
                    "severity": spec["severity"],
                    "title": spec["title"],
                    "summary": f"Matched indicator(s): {', '.join(hits[:5])}.",
                    "evidence": {"terms": hits[:8], "excerpt": _excerpt(text, hits)},
                    "impact": spec["impact"],
                    "remediation": spec["remediation"],
                    "limitations": [
                        "Keyword matching can produce false positives and does not prove fraud.",
                        "The message content is untrusted user input.",
                    ],
                    "authoritative": False,
                    "matched_terms": hits[:8],
                }
            )

    if urls:
        findings.append(
            {
                "rule_id": "message.contains_link",
                "severity": "info",
                "title": "External links extracted",
                "summary": f"{len(urls)} URL(s) found; each is inspected with SSRF-safe checks.",
                "evidence": {"urls": [u[:200] for u in urls[:5]]},
                "impact": "Links are the usual delivery path for phishing pages.",
                "remediation": "Do not open links until their destination has been verified.",
                "limitations": ["TrustLens inspects at most the first two URLs in depth."],
                "authoritative": False,
            }
        )

    if not findings:
        findings.append(
            {
                "rule_id": "message.no_patterns",
                "severity": "info",
                "title": "No strong social-engineering pattern matched",
                "summary": "No urgency, credential, payment or impersonation pattern was detected by the deterministic rules.",
                "evidence": {"characters": len(text)},
                "impact": "Absence of patterns does not make the message trustworthy.",
                "remediation": "Continue to verify unsolicited requests through an independent channel.",
                "limitations": ["Scams in other languages or unusual phrasing may be missed."],
                "authoritative": False,
            }
        )

    high_count = sum(1 for f in findings if f["severity"] in {"high", "critical"})
    severity = max((f["severity"] for f in findings), key=lambda s: _SEVERITY_ORDER[s], default="info")

    return {
        "status": "completed",
        "severity": severity,
        "summary": (
            f"{len(findings)} message pattern(s); {high_count} high-severity signal(s)."
            if findings
            else "No message patterns detected."
        ),
        "evidence": {
            "characters": len(text),
            "urls": urls[:5],
            "email_count": len(emails),
            "phone_count": len(phones),
            "ip_count": len(ips),
            "crypto_wallet_count": len(btc) + len(eth),
            "matched_categories": matched_terms,
            "redacted_excerpt": redact_text(text[:400]),
        },
        "findings": findings,
        "indicators": indicators,
        "urls": urls[:10],
        "email_masks": [mask_email(email) for email in emails[:5]],
        "phone_masks": [mask_phone(phone) for phone in phones[:5]],
        "redacted_text": redact_text(text[:2000]),
        "limitations": [
            "Deterministic keyword patterns cannot understand every language or context.",
            "Suspicious language alone is not evidence of fraud.",
            "TrustLens does not verify the sender's identity.",
        ],
    }
