"""Versioned, deterministic risk engine.

AI can explain evidence; it can never set or override this classification.
"""

from __future__ import annotations

from dataclasses import dataclass, field

RULESET_VERSION = "trustlens-rules-v1"

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}

RISK_CLASSES = (
    "Low Risk",
    "Suspicious",
    "High Risk",
    "Confirmed Malicious",
    "Inconclusive",
)

RISK_DEFINITIONS = {
    "Low Risk": "No significant malicious indicators were found in the checks that actually ran. This is not proof of safety.",
    "Suspicious": "At least one meaningful indicator needs further investigation.",
    "High Risk": "Multiple significant indicators were supported by evidence.",
    "Confirmed Malicious": "An authoritative threat-intelligence source or sufficiently validated evidence confirms malicious activity.",
    "Inconclusive": "Evidence is insufficient, key sources were unavailable, or relevant checks could not run.",
}

NEXT_ACTIONS = {
    "Low Risk": [
        "No action is strictly required, but the site has not been proven safe.",
        "Avoid entering credentials on pages reached through unsolicited links.",
    ],
    "Suspicious": [
        "Do not enter credentials or payment details.",
        "Verify the domain through the organisation's official website or phone number.",
    ],
    "High Risk": [
        "Do not open the link or submit any information.",
        "Block the domain and report the message to your organisation's security team.",
        "If credentials were entered, change them and revoke active sessions.",
    ],
    "Confirmed Malicious": [
        "Do not open the link under any circumstances.",
        "If you interacted with the page, change affected passwords and contact your bank or IT team.",
        "Report the URL to the relevant threat-intelligence source.",
    ],
    "Inconclusive": [
        "Treat the result as unknown, not safe.",
        "Wait for sources to recover or verify the site manually through an official channel.",
    ],
}


@dataclass
class RiskFinding:
    rule_id: str
    severity: str
    title: str
    check_id: str
    evidence: dict = field(default_factory=dict)
    authoritative: bool = False

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity, 0)


@dataclass
class RiskAssessment:
    classification: str
    score: int
    confidence: float
    coverage: float
    ruleset_version: str
    reasons: list[dict]
    limitations: list[str]
    recommended_actions: list[str]
    degraded: bool = False

    def as_dict(self) -> dict:
        return {
            "classification": self.classification,
            "score": self.score,
            "confidence": self.confidence,
            "coverage": self.coverage,
            "ruleset_version": self.ruleset_version,
            "reasons": self.reasons,
            "limitations": self.limitations,
            "recommended_actions": self.recommended_actions,
            "definition": RISK_DEFINITIONS[self.classification],
            "degraded": self.degraded,
        }


def assess(
    findings: list[RiskFinding],
    *,
    completed_checks: int,
    applicable_checks: int,
    input_type: str,
    unavailable_sources: list[str] | None = None,
) -> RiskAssessment:
    unavailable_sources = unavailable_sources or []
    coverage = round(completed_checks / applicable_checks, 3) if applicable_checks else 0.0
    degraded = bool(unavailable_sources)

    significant = [f for f in findings if f.severity in {"critical", "high"}]
    authoritative = [f for f in findings if f.authoritative]
    raw_score = sum(f.weight for f in findings)
    score = max(0, min(100, raw_score))

    if authoritative:
        classification = "Confirmed Malicious"
    elif len(significant) >= 2 and score >= 50:
        classification = "High Risk"
    elif significant or score >= 20:
        classification = "Suspicious"
    elif coverage >= 0.5:
        classification = "Low Risk"
    else:
        classification = "Inconclusive"

    # Degraded assessments never silently become "Low Risk".
    if classification == "Low Risk" and degraded and coverage < 0.75:
        classification = "Inconclusive"

    base_confidence = 0.35 + 0.5 * coverage + 0.1 * min(len(significant), 2)
    if classification == "Inconclusive":
        base_confidence = min(base_confidence, 0.5)
    if authoritative:
        base_confidence = max(base_confidence, 0.8)
    confidence = round(min(0.95, base_confidence), 2)

    reasons = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "weight": f.weight,
            "check_id": f.check_id,
            "authoritative": f.authoritative,
        }
        for f in sorted(findings, key=lambda x: (-x.weight, x.rule_id))
    ]

    limitations: list[str] = [
        "TrustLens performs passive checks only and cannot prove a site is safe.",
        "Similarity and keyword heuristics can produce false positives.",
    ]
    if unavailable_sources:
        limitations.append(
            "Unavailable sources: " + ", ".join(sorted(set(unavailable_sources))) + ". Their absence is not a clean result."
        )
    if coverage < 1:
        limitations.append(
            f"Evidence coverage was {int(coverage * 100)}% ({completed_checks}/{applicable_checks} applicable checks completed)."
        )
    if input_type == "message":
        limitations.append("Message analysis is a heuristic aid, not proof of fraud.")

    actions = list(NEXT_ACTIONS[classification])
    for finding in findings:
        remediation = finding.evidence.get("remediation")
        if isinstance(remediation, str) and remediation and remediation not in actions:
            actions.append(remediation)
    actions = actions[:7]

    return RiskAssessment(
        classification=classification,
        score=score,
        confidence=confidence,
        coverage=coverage,
        ruleset_version=RULESET_VERSION,
        reasons=reasons,
        limitations=limitations,
        recommended_actions=actions,
        degraded=degraded,
    )
