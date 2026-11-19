"""External threat-intelligence adapters with honest outage handling.

A timeout or an API error is recorded as ``unavailable`` — never as a clean
result. A "no match" is likewise not proof of safety.
"""

from __future__ import annotations

import httpx

from ..config import Settings
from ..security.redaction import safe_error


def _client(timeout: float) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": "TrustLens/1.0 (threat-intelligence lookup)"},
    )


def check_urlhaus(url: str, settings: Settings) -> dict:
    if not settings.threat_intel_enabled:
        return {
            "status": "not_run",
            "source": "URLhaus",
            "summary": "Threat-intelligence lookups are disabled.",
            "findings": [],
            "limitations": ["Threat intelligence was disabled by configuration."],
        }
    headers = {}
    if settings.urlhaus_auth_key:
        headers["Auth-Key"] = settings.urlhaus_auth_key
    try:
        with _client(settings.urlhaus_timeout_seconds) as client:
            response = client.post(
                settings.urlhaus_api_url, data={"url": url}, headers=headers
            )
        if response.status_code == 429:
            return {
                "status": "unavailable",
                "source": "URLhaus",
                "summary": "URLhaus rate limit reached; no reputation result was obtained.",
                "findings": [],
                "limitations": ["The source is rate-limited. A missing result must not be read as safe."],
            }
        if response.status_code >= 400:
            return {
                "status": "unavailable",
                "source": "URLhaus",
                "summary": f"URLhaus returned HTTP {response.status_code}.",
                "findings": [],
                "limitations": ["Threat intelligence was unavailable; the assessment is less complete."],
            }
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {
            "status": "unavailable",
            "source": "URLhaus",
            "summary": f"URLhaus lookup failed: {safe_error(exc, 120)}",
            "findings": [],
            "limitations": ["A failed query is not a clean query. Treat reputation as unknown."],
        }

    query_status = str(data.get("query_status", "unknown")).lower()
    if query_status in {"no_results", "not_found", "ok_no_results"}:
        return {
            "status": "completed",
            "source": "URLhaus",
            "summary": "No URLhaus match for this exact URL.",
            "findings": [],
            "evidence": {"query_status": query_status},
            "limitations": [
                "URLhaus matches exact URLs; a different but equivalent URL may still be listed.",
                "No match is not evidence of safety.",
            ],
        }
    if query_status not in {"is_blacklisted", "ok"}:
        return {
            "status": "unavailable",
            "source": "URLhaus",
            "summary": f"URLhaus returned an unrecognised status ({query_status}).",
            "findings": [],
            "limitations": ["Provider response format may have changed."],
        }

    url_status = str(data.get("url_status", "")).lower()
    threat = str(data.get("threat", "unknown"))
    tags = data.get("tags") or []
    reference = data.get("urlhaus_reference") or data.get("urlhaus_reference_url")
    date_added = data.get("date_added")
    authoritative = url_status == "online"
    findings = [
        {
            "rule_id": "intel.urlhaus_match",
            "severity": "critical" if authoritative else "high",
            "title": "Listed in URLhaus" + (" as online" if authoritative else " (historical entry)"),
            "summary": (
                f"URLhaus reports this URL as {url_status or 'listed'} for threat type '{threat}'."
            ),
            "evidence": {
                "reference": reference,
                "threat": threat,
                "tags": tags[:10],
                "url_status": url_status,
                "date_added": date_added,
            },
            "impact": "Visiting or submitting data to this URL can lead to malware delivery or credential theft.",
            "remediation": "Do not open the link. Block the URL and report it if it reached you unsolicited.",
            "limitations": [
                "URLhaus data is community-contributed and can lag or contain false positives.",
                "A historical (offline) entry does not prove the URL is currently dangerous.",
            ],
            "authoritative": authoritative,
        }
    ]
    return {
        "status": "completed",
        "source": "URLhaus",
        "summary": f"URLhaus match: {threat} ({url_status or 'status unknown'}).",
        "evidence": {
            "query_status": query_status,
            "url_status": url_status,
            "threat": threat,
            "tags": tags[:10],
            "reference": reference,
            "date_added": date_added,
            "reporter": data.get("reporter"),
        },
        "findings": findings,
        "limitations": [
            "URLhaus matches the submitted URL string, not every variant or redirect.",
            "A match is authoritative threat intelligence, but it does not describe this site's current content.",
        ],
    }


def check_certificate_transparency(domain: str, settings: Settings) -> dict:
    if not settings.ct_lookup_enabled:
        return {
            "status": "not_run",
            "source": "crt.sh",
            "summary": "Certificate Transparency lookup is disabled.",
            "findings": [],
            "limitations": ["CT lookup disabled by configuration."],
        }
    try:
        with _client(settings.ct_timeout_seconds) as client:
            response = client.get(
                settings.crt_sh_url,
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
            )
        if response.status_code >= 400:
            return {
                "status": "unavailable",
                "source": "crt.sh",
                "summary": f"crt.sh returned HTTP {response.status_code}.",
                "findings": [],
                "limitations": ["Certificate Transparency data was unavailable."],
            }
        if len(response.content) > 4_000_000:
            return {
                "status": "unavailable",
                "source": "crt.sh",
                "summary": "crt.sh response exceeded the safe size limit.",
                "findings": [],
                "limitations": ["Large CT responses are truncated by policy."],
            }
        rows = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {
            "status": "unavailable",
            "source": "crt.sh",
            "summary": f"crt.sh lookup failed: {safe_error(exc, 120)}",
            "findings": [],
            "limitations": ["Certificate Transparency availability is not guaranteed."],
        }

    if not isinstance(rows, list) or not rows:
        return {
            "status": "completed",
            "source": "crt.sh",
            "summary": "No Certificate Transparency records returned for this domain.",
            "findings": [],
            "evidence": {"records": 0},
            "limitations": ["Absence of CT records can be normal for very new domains or query failures."],
        }

    issuers: dict[str, int] = {}
    names: set[str] = set()
    dates: list[str] = []
    wildcard = 0
    for row in rows[:500]:
        if not isinstance(row, dict):
            continue
        issuer = str(row.get("issuer_name", ""))[:200]
        if issuer:
            issuers[issuer] = issuers.get(issuer, 0) + 1
        name_value = str(row.get("name_value", ""))
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name:
                names.add(name)
                if name.startswith("*."):
                    wildcard += 1
        if row.get("not_before"):
            dates.append(str(row.get("not_before")))

    facts = {
        "record_count": len(rows),
        "unique_names": len(names),
        "issuer_count": len(issuers),
        "top_issuers": sorted(issuers.items(), key=lambda kv: kv[1], reverse=True)[:5],
        "wildcard_entries": wildcard,
        "sample_names": sorted(names)[:8],
        "latest_not_before": max(dates) if dates else None,
    }
    findings: list[dict] = []
    if len(issuers) > 5:
        findings.append(
            {
                "rule_id": "ct.many_issuers",
                "severity": "low",
                "title": "Many certificate authorities observed",
                "summary": f"CT logs show {len(issuers)} distinct issuers for this domain family.",
                "evidence": {"issuers": facts["top_issuers"]},
                "impact": "Multiple issuers can widen the set of parties able to issue certificates for the domain.",
                "remediation": "The domain owner should review CAA records and unexpected issuances.",
                "limitations": ["Large organisations legitimately use several CAs."],
                "authoritative": False,
            }
        )
    return {
        "status": "completed",
        "source": "crt.sh",
        "summary": f"{len(rows)} Certificate Transparency record(s) across {len(issuers)} issuer(s).",
        "evidence": facts,
        "findings": findings,
        "limitations": [
            "crt.sh aggregates public logs and may be incomplete or rate-limited.",
            "A CT record proves a certificate was issued, not that it is currently trusted or in use.",
        ],
    }
