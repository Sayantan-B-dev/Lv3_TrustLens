"""Passive website security assessment from response headers and HTML."""

from __future__ import annotations


def _finding(rule_id, severity, title, summary, evidence, impact, remediation):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "summary": summary,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
        "limitations": [
            "Header checks observe only the final response; some protections are applied at a proxy not visible here.",
            "TrustLens performs passive inspection only and never attempts exploitation.",
        ],
        "authoritative": False,
    }


def analyse_headers(final_url: str, scheme: str, headers: dict[str, str], body: str, status: int | None, reachable: bool) -> dict:
    findings: list[dict] = []
    facts: dict = {}

    if not reachable:
        return {
            "status": "unavailable",
            "severity": "info",
            "summary": "The site could not be reached, so passive header checks did not run.",
            "evidence": {"final_url": final_url},
            "facts": {},
            "findings": [],
            "limitations": ["Transport or verification failures prevent header inspection."],
        }

    facts["status_code"] = status
    facts["final_url"] = final_url
    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    facts["server"] = server
    facts["powered_by"] = powered_by

    if not final_url.lower().startswith("https://"):
        findings.append(
            _finding(
                "web.no_https",
                "medium",
                "Site is served without HTTPS",
                "The final page was delivered over plain HTTP.",
                {"final_url": final_url},
                "Traffic can be read and modified in transit, including credentials and session cookies.",
                "The operator should serve the site over HTTPS and redirect HTTP traffic.",
            )
        )

    hsts = headers.get("strict-transport-security", "")
    facts["hsts"] = hsts or None
    if not hsts:
        findings.append(
            _finding(
                "web.missing_hsts",
                "low",
                "HSTS header is missing",
                "The response does not instruct browsers to require HTTPS for future visits.",
                {"header": "Strict-Transport-Security"},
                "Users remain exposed to protocol-downgrade attacks on the first request.",
                "Add Strict-Transport-Security with a long max-age and includeSubDomains where appropriate.",
            )
        )
    else:
        digits = "".join(ch for ch in hsts.split(";")[0] if ch.isdigit())
        max_age = int(digits) if digits else 0
        facts["hsts_max_age"] = max_age
        if max_age < 15552000:
            findings.append(
                _finding(
                    "web.weak_hsts",
                    "low",
                    "HSTS max-age is short",
                    f"HSTS max-age is {max_age} seconds; six months or more is recommended.",
                    {"hsts": hsts},
                    "A short HSTS lifetime gives less protection against downgrade attacks.",
                    "Increase max-age to at least 15552000 seconds.",
                )
            )

    csp = headers.get("content-security-policy", "")
    facts["csp"] = bool(csp)
    if not csp:
        findings.append(
            _finding(
                "web.missing_csp",
                "low",
                "Content-Security-Policy is missing",
                "No CSP header was observed.",
                {"header": "Content-Security-Policy"},
                "Without CSP, injected scripts have fewer browser-enforced restrictions.",
                "Deploy a restrictive CSP, starting in report-only mode if needed.",
            )
        )

    if not headers.get("x-content-type-options", "").lower().startswith("nosniff"):
        findings.append(
            _finding(
                "web.missing_nosniff",
                "low",
                "MIME sniffing protection is missing",
                "X-Content-Type-Options: nosniff was not observed.",
                {"header": "X-Content-Type-Options"},
                "Browsers may misinterpret file types, enabling content-sniffing attacks.",
                "Send X-Content-Type-Options: nosniff.",
            )
        )

    frame_options = headers.get("x-frame-options", "")
    csp_frames = "frame-ancestors" in csp.lower()
    facts["clickjacking_protection"] = bool(frame_options or csp_frames)
    if not frame_options and not csp_frames:
        findings.append(
            _finding(
                "web.missing_frame_protection",
                "low",
                "Clickjacking protection is missing",
                "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
                {"x_frame_options": frame_options or None, "csp": bool(csp)},
                "The site may be embedded in an attacker-controlled frame to trick users into clicking.",
                "Send X-Frame-Options: DENY or a CSP frame-ancestors directive.",
            )
        )

    if not headers.get("referrer-policy"):
        findings.append(
            _finding(
                "web.missing_referrer_policy",
                "info",
                "Referrer-Policy is missing",
                "The response does not define a referrer policy.",
                {"header": "Referrer-Policy"},
                "URLs containing sensitive parameters may leak to third parties through the Referer header.",
                "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
            )
        )

    if not headers.get("permissions-policy"):
        findings.append(
            _finding(
                "web.missing_permissions_policy",
                "info",
                "Permissions-Policy is missing",
                "The response does not restrict browser features for embedded content.",
                {"header": "Permissions-Policy"},
                "Unused browser capabilities remain available to page content.",
                "Send a Permissions-Policy that disables unneeded features.",
            )
        )

    if powered_by:
        findings.append(
            _finding(
                "web.version_disclosure",
                "low",
                "Technology version is disclosed",
                f"The response advertises '{powered_by}'.",
                {"x_powered_by": powered_by, "server": server},
                "Version disclosure helps attackers target known vulnerabilities.",
                "Remove X-Powered-By and detailed Server banners.",
            )
        )

    if body and final_url.lower().startswith("https://"):
        lowered = body.lower()
        mixed = []
        for needle in ("src=\"http://", "href=\"http://", "url(http://"):
            if needle in lowered and needle not in mixed:
                mixed.append(needle)
        facts["mixed_content_hints"] = len(mixed)
        if mixed:
            findings.append(
                _finding(
                    "web.mixed_content",
                    "medium",
                    "Mixed-content references detected",
                    "The HTML appears to load subresources over plain HTTP.",
                    {"patterns": mixed},
                    "Browsers may block the resources or expose them to tampering.",
                    "Serve every subresource over HTTPS.",
                )
            )

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severity = max((f["severity"] for f in findings), key=lambda s: severity_rank[s], default="info")
    return {
        "status": "completed",
        "severity": severity,
        "summary": (
            "No common header weaknesses were observed in this response."
            if not findings
            else f"{len(findings)} passive configuration finding(s)."
        ),
        "evidence": {"headers": headers, "facts": facts, "final_url": final_url},
        "facts": facts,
        "findings": findings,
        "limitations": [
            "Only the final response is inspected.",
            "Absence of a finding is not proof that the site is secure.",
        ],
    }
