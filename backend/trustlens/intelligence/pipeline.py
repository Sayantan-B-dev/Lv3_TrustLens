"""The investigation pipeline.

One traceable path: normalise input → deterministic checks → evidence records
→ deterministic risk engine → optional AI explanation. Every check produces a
persisted record with status, source, evidence and limitations. Failures are
recorded as ``unavailable``/``error`` and reduce evidence coverage; they are
never silently treated as clean results.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pymongo.database import Database

from ..ai.explain import explain
from ..config import Settings
from ..intelligence import threat_intel
from ..intelligence.correlation import correlate
from ..intelligence.dns import analyse_dns
from ..intelligence.domain import analyse_domain, registrable_domain
from ..intelligence.headers import analyse_headers
from ..intelligence.http_probe import FetchResult, analyse_redirects, follow
from ..intelligence.messages import analyse_message
from ..intelligence.normalize import (
    InvalidInput,
    URLInfo,
    normalize_url,
    redact_url_for_display,
)
from ..intelligence.risk import (
    RISK_DEFINITIONS,
    RULESET_VERSION,
    RiskAssessment,
    RiskFinding,
    assess,
)
from ..intelligence.tls import analyse_tls
from ..models import utcnow
from ..security.canonical import sha256_hex
from ..security.redaction import mask_email, mask_phone, safe_error

CHECK_CATALOG = {
    "url.structure": {
        "label": "URL structure",
        "category": "url",
        "description": "Normalise the URL and inspect its structure safely.",
    },
    "domain.heuristics": {
        "label": "Domain heuristics",
        "category": "domain",
        "description": "IDN/homograph, typosquatting, impersonation and shortener signals.",
    },
    "dns": {
        "label": "DNS records",
        "category": "dns",
        "description": "Public A/AAAA, CNAME, MX, NS and TXT records.",
    },
    "redirects": {
        "label": "Redirect chain",
        "category": "web",
        "description": "Follow revalidated redirects with SSRF protections.",
    },
    "threat_intel": {
        "label": "Threat intelligence",
        "category": "intel",
        "description": "URLhaus reputation for this exact URL, with honest outage handling.",
    },
    "tls": {
        "label": "TLS & certificate",
        "category": "tls",
        "description": "Handshake, chain, hostname, expiry and algorithm analysis.",
    },
    "headers": {
        "label": "Website security",
        "category": "web",
        "description": "Passive HTTPS, header and mixed-content assessment.",
    },
    "ct": {
        "label": "Certificate Transparency",
        "category": "tls",
        "description": "Public CT records and issuer diversity from crt.sh.",
    },
    "message.heuristics": {
        "label": "Message patterns",
        "category": "message",
        "description": "Social-engineering patterns and IOC extraction.",
    },
    "correlation": {
        "label": "IOC correlation",
        "category": "correlation",
        "description": "Exact-match correlation against earlier investigations.",
    },
    "ai": {
        "label": "Explanation",
        "category": "ai",
        "description": "Evidence-grounded explanation with deterministic fallback.",
    },
}

DEFAULT_CHECKS = [
    "url.structure",
    "domain.heuristics",
    "dns",
    "redirects",
    "threat_intel",
    "tls",
    "headers",
    "ct",
    "correlation",
    "ai",
]

MESSAGE_DEFAULT_CHECKS = [
    "message.heuristics",
    "url.structure",
    "domain.heuristics",
    "dns",
    "redirects",
    "threat_intel",
    "tls",
    "headers",
    "ct",
    "correlation",
    "ai",
]

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Outcome:
    check_id: str
    category: str
    status: str
    severity: str
    title: str
    summary: str
    evidence: dict = field(default_factory=dict)
    source: str = "TrustLens"
    source_timestamp: str | None = None
    limitations: list[str] = field(default_factory=list)
    impact: str | None = None
    remediation: str | None = None
    duration_ms: int = 0
    findings: list[dict] = field(default_factory=list)


def default_checks(input_type: str) -> list[str]:
    return list(MESSAGE_DEFAULT_CHECKS if input_type == "message" else DEFAULT_CHECKS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _worst_severity(findings: list[dict], fallback: str = "info") -> str:
    return max(
        (f.get("severity", "info") for f in findings),
        key=lambda s: SEVERITY_RANK.get(s, 0),
        default=fallback,
    )


def _outcome(
    *,
    check_id: str,
    category: str,
    title: str,
    result: dict,
    source: str,
    duration_ms: int,
) -> Outcome:
    findings = result.get("findings") or []
    return Outcome(
        check_id=check_id,
        category=category,
        status=result.get("status", "completed"),
        severity=result.get("severity") or _worst_severity(findings),
        title=title,
        summary=result.get("summary", ""),
        evidence=result.get("evidence") or {},
        source=result.get("source", source),
        source_timestamp=result.get("source_timestamp") or _now_iso(),
        limitations=result.get("limitations") or [],
        impact=result.get("impact"),
        remediation=result.get("remediation"),
        duration_ms=duration_ms,
        findings=findings,
    )


def _not_run(check_id: str, category: str, title: str, reason: str) -> Outcome:
    return Outcome(
        check_id=check_id,
        category=category,
        status="not_run",
        severity="info",
        title=title,
        summary=reason,
        limitations=[reason],
    )


def _failed(check_id: str, category: str, title: str, exc: BaseException, duration_ms: int = 0) -> Outcome:
    return Outcome(
        check_id=check_id,
        category=category,
        status="error",
        severity="info",
        title=title,
        summary=f"Check failed: {safe_error(exc, 180)}",
        limitations=["This check did not complete; its absence is not a clean result."],
        duration_ms=duration_ms,
    )


def _url_indicators(info: URLInfo) -> list[dict]:
    return [
        {
            "type": "ip" if info.is_ip_literal else "domain",
            "value": info.host[:500],
            "confidence": 0.9,
            "provenance": "url-normalisation",
        },
        {
            "type": "url",
            "value": redact_url_for_display(info.url)[:500],
            "confidence": 0.9,
            "provenance": "url-normalisation",
        },
    ]


def _analyse_url(
    url_text: str,
    *,
    suffix: str,
    requested: set[str],
    settings: Settings,
    depth: int = 0,
) -> tuple[list[Outcome], list[dict]]:
    outcomes: list[Outcome] = []
    indicators: list[dict] = []

    structure_started = time.monotonic()
    try:
        info = normalize_url(url_text)
    except InvalidInput as exc:
        outcomes.append(
            Outcome(
                check_id=f"url.structure{suffix}",
                category="url",
                status="error",
                severity="high",
                title="URL could not be normalised",
                summary=str(exc),
                limitations=["An unparseable URL cannot be inspected safely."],
                duration_ms=int((time.monotonic() - structure_started) * 1000),
            )
        )
        return outcomes, indicators

    outcomes.append(
        Outcome(
            check_id=f"url.structure{suffix}",
            category="url",
            status="completed",
            severity="info",
            title="URL normalised",
            summary=f"Scheme {info.scheme}, host {info.host}, port {info.port}.",
            evidence={
                "display": info.display,
                "scheme": info.scheme,
                "host": info.host,
                "unicode_host": info.unicode_host,
                "port": info.port,
                "port_allowed": info.port_allowed,
                "is_ip_literal": info.is_ip_literal,
                "had_credentials": info.had_credentials,
                "path_length": len(info.path),
            },
            duration_ms=int((time.monotonic() - structure_started) * 1000),
        )
    )
    indicators.extend(_url_indicators(info))

    if "domain.heuristics" in requested:
        started = time.monotonic()
        try:
            domain_result = analyse_domain(info)
            outcome = _outcome(
                check_id=f"domain.heuristics{suffix}",
                category="domain",
                title="Domain heuristics",
                result={
                    **domain_result,
                    "summary": (
                        f"{len(domain_result['findings'])} domain signal(s) identified."
                        if domain_result["findings"]
                        else "No domain-name deception signals matched."
                    ),
                    "evidence": domain_result["facts"],
                    "severity": _worst_severity(domain_result["findings"]),
                    "source": "TrustLens deterministic heuristics",
                    "limitations": [
                        "Similarity heuristics can produce false positives.",
                        "A clean result does not prove the domain is trustworthy.",
                    ],
                },
                source="TrustLens heuristics",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            outcomes.append(outcome)
        except Exception as exc:  # pragma: no cover - defensive
            outcomes.append(_failed(f"domain.heuristics{suffix}", "domain", "Domain heuristics", exc))

    if "dns" in requested and not info.is_ip_literal:
        started = time.monotonic()
        try:
            result = analyse_dns(info.host)
            outcomes.append(
                _outcome(
                    check_id=f"dns{suffix}",
                    category="dns",
                    title="DNS records",
                    result=result,
                    source="public DNS",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            )
        except Exception as exc:
            outcomes.append(_failed(f"dns{suffix}", "dns", "DNS records", exc))
    elif "dns" in requested:
        outcomes.append(
            _not_run(f"dns{suffix}", "dns", "DNS records", "Not applicable to an IP-literal host.")
        )

    fetch_needed = bool({"redirects", "headers"} & requested)
    fetch_result: FetchResult | None = None
    if fetch_needed:
        started = time.monotonic()
        try:
            fetch_result = follow(info.url, settings)
        except Exception as exc:
            fetch_result = FetchResult(url=info.url, final_url=info.url, error=safe_error(exc, 200))
        fetch_ms = int((time.monotonic() - started) * 1000)

        if "redirects" in requested:
            if fetch_result.status is None:
                outcomes.append(
                    Outcome(
                        check_id=f"redirects{suffix}",
                        category="web",
                        status="unavailable",
                        severity="info",
                        title="Redirect chain",
                        summary=f"Redirects could not be inspected: {fetch_result.error or 'request failed'}",
                        evidence={"error": fetch_result.error, "chain": fetch_result.redirect_chain},
                        limitations=["The destination was not reachable through safe fetching."],
                        duration_ms=fetch_ms,
                    )
                )
            else:
                redirect_result = analyse_redirects(fetch_result)
                outcomes.append(
                    _outcome(
                        check_id=f"redirects{suffix}",
                        category="web",
                        title="Redirect chain",
                        result={
                            **redirect_result,
                            "summary": (
                                f"{len(fetch_result.redirect_chain)} redirect(s); final host "
                                f"{info.host if not fetch_result.final_url else fetch_result.final_url[:120]}."
                            ),
                            "severity": _worst_severity(redirect_result.get("findings", [])),
                            "source": "TrustLens safe fetcher",
                            "limitations": [
                                "Only a bounded number of redirects are followed.",
                                "JavaScript or meta-refresh redirects are not executed.",
                            ],
                        },
                        source="TrustLens safe fetcher",
                        duration_ms=fetch_ms,
                    )
                )

        if "headers" in requested:
            if fetch_result.status is None:
                outcomes.append(
                    Outcome(
                        check_id=f"headers{suffix}",
                        category="web",
                        status="unavailable",
                        severity="info",
                        title="Website security headers",
                        summary=f"Passive header inspection could not run: {fetch_result.error or 'request failed'}",
                        evidence={"error": fetch_result.error},
                        limitations=["No response was received, so headers were not assessed."],
                        duration_ms=fetch_ms,
                    )
                )
            else:
                header_result = analyse_headers(
                    fetch_result.final_url,
                    info.scheme,
                    fetch_result.headers,
                    fetch_result.body,
                    fetch_result.status,
                    reachable=True,
                )
                outcomes.append(
                    _outcome(
                        check_id=f"headers{suffix}",
                        category="web",
                        title="Website security headers",
                        result=header_result,
                        source="passive HTTP inspection",
                        duration_ms=fetch_ms,
                    )
                )

        if fetch_result.status is not None and fetch_result.final_url != info.url:
            try:
                final_info = normalize_url(fetch_result.final_url)
                indicators.append(
                    {
                        "type": "ip" if final_info.is_ip_literal else "domain",
                        "value": final_info.host[:500],
                        "confidence": 0.85,
                        "provenance": "redirect-destination",
                    }
                )
                indicators.extend(_url_indicators(final_info)[1:])
            except InvalidInput:
                pass

    if "tls" in requested:
        if info.scheme != "https":
            outcomes.append(
                _not_run(
                    f"tls{suffix}",
                    "tls",
                    "TLS & certificate",
                    "Not applicable: the submitted URL uses plain HTTP.",
                )
            )
        else:
            started = time.monotonic()
            try:
                result = analyse_tls(
                    info.host,
                    info.port,
                    ip=fetch_result.resolved_ip if fetch_result else None,
                )
                outcomes.append(
                    _outcome(
                        check_id=f"tls{suffix}",
                        category="tls",
                        title="TLS & certificate",
                        result=result,
                        source="direct TLS handshake",
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                )
            except Exception as exc:
                outcomes.append(_failed(f"tls{suffix}", "tls", "TLS & certificate", exc))

    if "threat_intel" in requested:
        started = time.monotonic()
        try:
            intel = threat_intel.check_urlhaus(info.url, settings)
            outcomes.append(
                _outcome(
                    check_id=f"threat_intel{suffix}",
                    category="intel",
                    title="Threat intelligence (URLhaus)",
                    result=intel,
                    source="URLhaus",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            )
        except Exception as exc:
            outcomes.append(_failed(f"threat_intel{suffix}", "intel", "Threat intelligence", exc))

        # Check the redirect destination too — the submitted URL may be a clean wrapper.
        if (
            depth == 0
            and fetch_result is not None
            and fetch_result.status is not None
            and fetch_result.final_url
            and fetch_result.final_url != info.url
        ):
            started = time.monotonic()
            try:
                final_intel = threat_intel.check_urlhaus(fetch_result.final_url, settings)
                final_outcome = _outcome(
                    check_id=f"threat_intel.destination{suffix}",
                    category="intel",
                    title="Threat intelligence (final destination)",
                    result=final_intel,
                    source="URLhaus",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
                final_outcome.evidence = {
                    **(final_outcome.evidence or {}),
                    "destination": redact_url_for_display(fetch_result.final_url),
                }
                outcomes.append(final_outcome)
            except Exception as exc:
                outcomes.append(
                    _failed(f"threat_intel.destination{suffix}", "intel", "Threat intelligence", exc)
                )

    if "ct" in requested and not info.is_ip_literal:
        started = time.monotonic()
        try:
            domain = registrable_domain(info.host)
            ct_result = threat_intel.check_certificate_transparency(domain, settings)
            ct_result["evidence"] = {**ct_result.get("evidence", {}), "queried_domain": domain}
            outcomes.append(
                _outcome(
                    check_id=f"ct{suffix}",
                    category="tls",
                    title="Certificate Transparency",
                    result=ct_result,
                    source="crt.sh",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            )
        except Exception as exc:
            outcomes.append(_failed(f"ct{suffix}", "tls", "Certificate Transparency", exc))

    return outcomes, indicators


def _prepare_indicators(raw: list[dict]) -> list[dict]:
    prepared: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        kind = str(item.get("type", ""))[:32]
        value = str(item.get("value", "")).strip()
        if not kind or not value:
            continue
        if kind == "email":
            normalized = "sha256:" + sha256_hex(value.lower())[:32]
            display = mask_email(value)
        elif kind == "phone":
            normalized = "sha256:" + sha256_hex(value.lower())[:32]
            display = mask_phone(value)
        else:
            normalized = value.lower().rstrip("/")
            display = value
        if normalized in seen:
            continue
        seen.add(normalized)
        prepared.append(
            {
                "type": kind,
                "value": display[:500],
                "normalized_value": normalized[:500],
                "confidence": float(item.get("confidence", 0.6)),
                "provenance": str(item.get("provenance", "deterministic"))[:120],
            }
        )
    return prepared[:60]


def _risk_findings(outcomes: list[Outcome]) -> list[RiskFinding]:
    findings: list[dict] = []
    for outcome in outcomes:
        if outcome.status not in {"completed", "unavailable", "error"}:
            continue
        for finding in outcome.findings or []:
            severity = finding.get("severity", "info")
            if severity == "info":
                continue
            findings.append(
                RiskFinding(
                    rule_id=str(finding.get("rule_id", "unknown")),
                    severity=severity,
                    title=str(finding.get("title", "Security finding")),
                    check_id=outcome.check_id,
                    evidence={"remediation": finding.get("remediation", "")},
                    authoritative=bool(finding.get("authoritative", False)),
                )
            )
    return findings


def _persisted_children(outcomes: list[Outcome], indicators: list[dict]) -> tuple[list[dict], list[dict]]:
    created_at = utcnow()
    checks = [
        {
            "id": index,
            "check_id": outcome.check_id[:80],
            "category": outcome.category[:40],
            "status": outcome.status[:24],
            "severity": outcome.severity[:16],
            "title": outcome.title[:200],
            "summary": outcome.summary or "",
            "evidence": {**(outcome.evidence or {}), "findings": outcome.findings or []},
            "source": outcome.source[:120],
            "source_timestamp": outcome.source_timestamp,
            "limitations": outcome.limitations or [],
            "impact": outcome.impact,
            "remediation": outcome.remediation,
            "duration_ms": outcome.duration_ms,
            "created_at": created_at,
        }
        for index, outcome in enumerate(outcomes, start=1)
    ]
    indicator_docs = [
        {
            "type": item["type"],
            "value": item["value"],
            "normalized_value": item["normalized_value"],
            "confidence": item["confidence"],
            "provenance": item["provenance"],
            "created_at": created_at,
        }
        for item in indicators
    ]
    return checks, indicator_docs


def _finalise(
    db: Database,
    investigation: dict,
    outcomes: list[Outcome],
    indicators: list[dict],
    settings: Settings,
    *,
    input_type: str,
    target: str,
    ai_enabled: bool,
) -> None:
    risk_findings = _risk_findings(outcomes)
    assessable = [
        o
        for o in outcomes
        if o.category != "ai" and o.status in {"completed", "unavailable", "error"}
    ]
    completed = [o for o in assessable if o.status == "completed"]
    unavailable = sorted(
        {o.check_id for o in assessable if o.status in {"unavailable", "error"}}
    )

    applicable = len(assessable)

    risk = assess(
        risk_findings,
        completed_checks=len(completed),
        applicable_checks=applicable,
        input_type=input_type,
        unavailable_sources=unavailable,
    )

    explanation = explain(
        settings,
        risk,
        outcomes,
        input_type=input_type,
        target=target,
        force_deterministic=not ai_enabled,
    )
    ai_outcome = Outcome(
        check_id="ai.explanation",
        category="ai",
        status="completed",
        severity="info",
        title="Evidence explanation",
        summary=explanation.payload["summary"],
        evidence=explanation.payload,
        source=explanation.provider,
        source_timestamp=_now_iso(),
        limitations=explanation.payload.get("limitations", []),
        findings=[],
    )
    outcomes.append(ai_outcome)

    top_findings = sorted(
        risk_findings, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.rule_id)
    )[:3]
    summary = (
        f"{risk.classification} — {RISK_DEFINITIONS[risk.classification]}"
        + (f" Key evidence: {'; '.join(f.title for f in top_findings)}." if top_findings else "")
    )

    # Risk evidence is stored on the risk outcome for transparent scoring.
    outcomes.insert(
        0,
        Outcome(
            check_id="risk.assessment",
            category="risk",
            status="completed",
            severity="info",
            title="Deterministic risk assessment",
            summary=risk.as_dict()["definition"],
            evidence=risk.as_dict(),
            source=f"TrustLens ruleset {risk.ruleset_version}",
            source_timestamp=_now_iso(),
            limitations=risk.limitations,
            findings=[],
        ),
    )

    checks, indicator_docs = _persisted_children(outcomes, indicators)
    update = {
        "risk_classification": risk.classification,
        "score": risk.score,
        "confidence": risk.confidence,
        "coverage": risk.coverage,
        "ruleset_version": RULESET_VERSION,
        "summary": summary[:2000],
        "ai_provider": explanation.provider,
        "ai_model": explanation.model,
        "ai_used": explanation.used,
        "checks_total": len(assessable),
        "checks_completed": len(completed),
        "status": "completed",
        "completed_at": utcnow(),
        "error": None,
        "checks": checks,
        "indicators": indicator_docs,
    }
    db.investigations.update_one({"_id": investigation["_id"]}, {"$set": update})
    investigation.update(update)


def run_pipeline(db: Database, investigation: dict, settings: Settings) -> dict:
    db.investigations.update_one(
        {"_id": investigation["_id"]},
        {"$set": {"status": "running", "started_at": utcnow(), "error": None}},
    )
    investigation.update({"status": "running", "started_at": utcnow(), "error": None})

    requested = {
        check
        for check in (investigation.get("checks_requested") or [])
        if isinstance(check, str)
    } or set(default_checks(investigation.get("input_type", "url")))

    outcomes: list[Outcome] = []
    indicators: list[dict] = []

    if investigation.get("input_type") == "message":
        started = time.monotonic()
        try:
            message_result = analyse_message(investigation.get("input_value") or "")
            indicators.extend(message_result.get("indicators", []))
            if "message.heuristics" in requested:
                outcomes.append(
                    _outcome(
                        check_id="message.heuristics",
                        category="message",
                        title="Scam message patterns",
                        result=message_result,
                        source="TrustLens deterministic heuristics",
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                )
            else:
                outcomes.append(
                    _not_run(
                        "message.heuristics",
                        "message",
                        "Scam message patterns",
                        "Disabled for this investigation.",
                    )
                )

            targets = message_result.get("urls", [])[:2]
            for index, url in enumerate(targets, start=1):
                suffix = f":link{index}"
                try:
                    link_outcomes, link_indicators = _analyse_url(
                        url,
                        suffix=suffix,
                        requested=requested,
                        settings=settings,
                    )
                    outcomes.extend(link_outcomes)
                    indicators.extend(link_indicators)
                except Exception as exc:  # pragma: no cover - defensive
                    outcomes.append(_failed(f"url.structure{suffix}", "url", "Extracted link", exc))
        except Exception as exc:
            outcomes.append(_failed("message.heuristics", "message", "Scam message patterns", exc))
    else:
        try:
            url_outcomes, url_indicators = _analyse_url(
                investigation.get("input_value") or "",
                suffix="",
                requested=requested,
                settings=settings,
            )
            outcomes.extend(url_outcomes)
            indicators.extend(url_indicators)
        except Exception as exc:  # pragma: no cover - defensive
            outcomes.append(_failed("url.structure", "url", "URL analysis", exc))

    prepared_indicators = _prepare_indicators(indicators)

    if "correlation" in requested:
        started = time.monotonic()
        try:
            correlation_result = correlate(db, investigation["_id"], prepared_indicators)
            outcomes.append(
                _outcome(
                    check_id="correlation",
                    category="correlation",
                    title="Threat correlation",
                    result={
                        "status": "completed",
                        "summary": correlation_result["summary"],
                        "evidence": {
                            "matches": correlation_result["matches"],
                            "indicator_count": len(prepared_indicators),
                        },
                        "findings": correlation_result.get("findings", []),
                        "severity": _worst_severity(correlation_result.get("findings", [])),
                        "source": "TrustLens indicator store",
                        "limitations": correlation_result["limitations"],
                    },
                    source="TrustLens indicator store",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            )
        except Exception as exc:
            outcomes.append(_failed("correlation", "correlation", "Threat correlation", exc))

    target = (
        "pasted message"
        if investigation.get("input_type") == "message"
        else investigation.get("display_value")
    )
    _finalise(
        db,
        investigation,
        outcomes,
        prepared_indicators,
        settings,
        input_type=investigation.get("input_type", "url"),
        target=target,
        ai_enabled="ai" in requested,
    )
    return investigation


def coverage_snapshot(investigation: dict) -> dict:
    return {
        "checks_total": investigation.get("checks_total", 0),
        "checks_completed": investigation.get("checks_completed", 0),
        "coverage": investigation.get("coverage"),
        "confidence": investigation.get("confidence"),
    }
