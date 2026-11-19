"""DNS record inspection with bounded timeouts."""

from __future__ import annotations

import dns.exception
import dns.resolver

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _query(resolver: dns.resolver.Resolver, name: str, record_type: str) -> list[str]:
    try:
        answer = resolver.resolve(name, record_type, lifetime=4.0)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        return []
    values: list[str] = []
    for record in answer:
        text = record.to_text().strip().strip('"')
        if record_type == "MX":
            preference, _, exchange = text.partition(" ")
            text = f"{exchange.rstrip('.')} ({preference})"
        elif record_type in {"CNAME", "NS"}:
            text = text.rstrip(".")
        values.append(text[:300])
    return values[:20]


def analyse_dns(host: str) -> dict:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 3.0
    resolver.lifetime = 4.0
    resolver.retry_servfail = False

    records: dict[str, list[str]] = {}
    for record_type in RECORD_TYPES:
        records[record_type] = _query(resolver, host, record_type)

    resolves = bool(records["A"] or records["AAAA"] or records["CNAME"])
    facts = {
        "records": records,
        "resolves": resolves,
        "has_mx": bool(records["MX"]),
        "has_spf": any("v=spf1" in value.lower() for value in records["TXT"]),
        "has_dmarc_hint": any("dmarc" in value.lower() for value in records["TXT"]),
    }
    findings: list[dict] = []
    if not resolves:
        findings.append(
            {
                "rule_id": "dns.no_resolution",
                "severity": "medium",
                "title": "Domain did not resolve",
                "summary": "No A, AAAA or CNAME record was returned for this host.",
                "evidence": {"host": host, "records": records},
                "impact": "A non-resolving domain cannot serve a legitimate page; it may be abandoned or not yet active.",
                "remediation": "Do not rely on this link. Confirm the address with the organisation through an independent channel.",
                "limitations": ["Resolver outages or filtering can also cause an empty answer."],
                "authoritative": False,
            }
        )
    if records["CNAME"]:
        findings.append(
            {
                "rule_id": "dns.cname_chain",
                "severity": "info",
                "title": "Canonical name alias present",
                "summary": "The hostname aliases another name; the destination was inspected separately.",
                "evidence": {"cname": records["CNAME"]},
                "impact": "Aliases are normal for hosted services but also hide the hosting provider.",
                "remediation": "None required; use this as context when reviewing hosting infrastructure.",
                "limitations": ["TrustLens resolves public DNS only and does not enumerate every record type."],
                "authoritative": False,
            }
        )
    return {
        "status": "completed",
        "records": records,
        "facts": facts,
        "findings": findings,
        "source": "public DNS resolver",
    }
