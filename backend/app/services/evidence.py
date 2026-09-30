"""Evidence correlation, scoring, and explainable verdicts.

Every detection signal is assigned to one of five categories:

- CRITICAL: confirmed threat intelligence or administrator enforcement.
- STRONG: direct evidence of impersonation, homograph deception, deceptive
  ownership, or credential-authority confusion.
- MEDIUM: meaningful but potentially ambiguous attack evidence.
- WEAK: contextual anomalies that cannot independently establish suspicion.
- CONTEXTUAL: trust-positive or neutral observations.

Weak evidence changes the score, but it cannot satisfy the evidence gate by
itself.  A suspicious verdict needs at least one strong signal or at least two
independent medium signals.  Related lexical findings share a capped group so
one typo cannot inflate the score several times.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CRITICAL = "critical"
STRONG = "strong"
MEDIUM = "medium"
WEAK = "weak"
CONTEXTUAL = "contextual"

SAFE = "SAFE"
UNKNOWN = "UNKNOWN"
SUSPICIOUS = "SUSPICIOUS"
HIGH_RISK = "HIGH_RISK"
MALICIOUS = "MALICIOUS"

LOW = "LOW"
MODERATE = "MODERATE"
HIGH = "HIGH"
CRITICAL_LEVEL = "CRITICAL"

# Initial evidence weights required by the detection architecture.
WEIGHTS: dict[str, int] = {
    "confirmed_threat_intelligence": 100,
    "manual_blocklist": 100,
    "known_malicious": 100,
    "content_policy_block": 100,
    "whitelist_policy_block": 100,
    "confirmed_homograph": 45,
    "punycode_impersonation": 40,
    "very_close_typosquat": 40,
    "deceptive_subdomain": 35,
    "credential_userinfo": 30,
    "brand_similarity": 25,
    "edit_distance_le_2": 25,
    "brand_prefix": 20,
    "brand_embedded": 20,
    "brand_token_match": 25,
    "brand_compound_modifier": 20,
    "critical_brand_match": 15,
    "tld_mismatch": 15,
    "high_risk_namespace": 15,
    "credential_brand_decoy": 15,
    "mixed_script": 30,
    "ip_host_with_credential": 20,
    "credential_path_with_suspicious_domain": 15,
    "external_redirect_target": 10,
    "encoded_obfuscation": 10,
    "deceptive_domain_construction": 25,
    "unknown_domain": 5,
    "not_in_trusted_database": 5,
    "suspicious_tld": 5,
    "login_keyword": 3,
    "redirect_parameter": 3,
    "unusual_encoding": 2,
    "long_url": 2,
    "non_http_scheme": 3,
}

# Related lexical evidence shares one capped contribution.  These groups do
# not prevent separate findings from appearing in the evidence report; they
# prevent the score from counting the same deception several times.
GROUP_CAPS: dict[str, int] = {
    "TYPO_SQUAT_GROUP": 40,
    "HOMOGRAPH_GROUP": 45,
}

GROUP_FOR_SIGNAL: dict[str, str] = {
    "very_close_typosquat": "TYPO_SQUAT_GROUP",
    "edit_distance_le_2": "TYPO_SQUAT_GROUP",
    "brand_similarity": "TYPO_SQUAT_GROUP",
    "brand_prefix": "TYPO_SQUAT_GROUP",
    "brand_embedded": "TYPO_SQUAT_GROUP",
    "brand_token_match": "TYPO_SQUAT_GROUP",
    "brand_compound_modifier": "TYPO_SQUAT_GROUP",
    "critical_brand_match": "TYPO_SQUAT_GROUP",
    "tld_mismatch": "TYPO_SQUAT_GROUP",
    "confirmed_homograph": "HOMOGRAPH_GROUP",
    "punycode_impersonation": "HOMOGRAPH_GROUP",
    "mixed_script": "HOMOGRAPH_GROUP",
}


@dataclass
class EvidenceItem:
    """One structured, explainable detection signal."""

    name: str
    category: str
    weight: int = 0
    explanation: str = ""
    matched_domain: str | None = None
    details: dict = field(default_factory=dict)


@dataclass
class EvidenceReport:
    critical: list[EvidenceItem] = field(default_factory=list)
    strong: list[EvidenceItem] = field(default_factory=list)
    medium: list[EvidenceItem] = field(default_factory=list)
    weak: list[EvidenceItem] = field(default_factory=list)
    contextual: list[EvidenceItem] = field(default_factory=list)
    score: int = 0
    classification: str = UNKNOWN
    risk_level: str = LOW
    confidence: float = 0.0
    explanation: list[str] = field(default_factory=list)
    strong_signals: int = 0
    medium_signals: int = 0

    def as_dict(self) -> dict:
        def names(items: list[EvidenceItem]) -> list[str]:
            seen: list[str] = []
            for item in items:
                if item.name not in seen:
                    seen.append(item.name)
            return seen

        return {
            "critical": names(self.critical),
            "strong": names(self.strong),
            "medium": names(self.medium),
            "weak": names(self.weak),
            "contextual": names(self.contextual),
        }


def apply_group_caps(items: list[EvidenceItem]) -> int:
    """Return the capped contribution of strong and medium evidence."""
    total = 0
    group_totals: dict[str, int] = {}
    for item in items:
        if item.category not in (STRONG, MEDIUM):
            continue
        weight = max(0, int(item.weight))
        group = GROUP_FOR_SIGNAL.get(item.name)
        if group:
            group_totals[group] = group_totals.get(group, 0) + weight
        else:
            total += weight
    for group, group_total in group_totals.items():
        total += min(group_total, GROUP_CAPS[group])
    return total


def sum_weak(items: list[EvidenceItem]) -> int:
    return sum(max(0, int(item.weight)) for item in items if item.category == WEAK)


def _band_classification(
    score: int,
    strong_count: int,
    medium_count: int,
    thresholds: dict[str, int],
) -> tuple[str, str]:
    """Fixed architecture bands, with configurable ceilings preserved.

    Defaults are 0-19 SAFE/LOW, 20-39 UNKNOWN/LOW, 40-59 SUSPICIOUS/MEDIUM,
    60-79 HIGH_RISK/HIGH, and 80-100 MALICIOUS/CRITICAL.  A gated strong or
    correlated-medium verdict cannot fall below SUSPICIOUS merely because its
    calibrated numeric score is small.
    """
    low = int(thresholds.get("low", 20))
    suspicious_ceiling = int(thresholds.get("moderate", 59))
    high_ceiling = int(thresholds.get("high", 79))
    gated = strong_count > 0 or medium_count >= 2

    if score <= low:
        return (SUSPICIOUS, MODERATE) if gated else (UNKNOWN, LOW)
    if score <= suspicious_ceiling:
        return SUSPICIOUS, MODERATE
    if score <= high_ceiling:
        return HIGH_RISK, HIGH
    return MALICIOUS, CRITICAL_LEVEL


def _confidence_for(report: EvidenceReport) -> float:
    contextual = {item.name for item in report.contextual}
    if report.critical:
        return 0.97
    if report.strong:
        return min(0.94, 0.86 + 0.02 * len(report.strong))
    if report.medium_signals >= 2:
        return min(0.86, 0.78 + 0.02 * report.medium_signals)
    confidence = 0.72
    if "valid_domain_structure" in contextual:
        confidence += 0.04
    if "no_reputation_data" in contextual:
        confidence += 0.03
    if "institutional_academic_namespace" in contextual:
        confidence += 0.03
    if "secure_scheme" in contextual:
        confidence += 0.03
    if "normal_tld" in contextual:
        confidence += 0.03
    if "reputation_verified_benign" in contextual:
        confidence += 0.05
    if "threat_intel_error" in contextual:
        confidence -= 0.08
    return round(max(0.55, min(0.90, confidence)), 2)


def correlate_evidence(
    items: list[EvidenceItem],
    thresholds: dict[str, int] | None = None,
) -> EvidenceReport:
    """Correlate structured evidence into a score, gate, and explanation."""
    report = EvidenceReport()
    for item in items:
        bucket = getattr(report, item.category, None)
        if isinstance(bucket, list):
            bucket.append(item)
    strong_count = len(report.strong)
    medium_count = len(report.medium)

    score = apply_group_caps([*report.strong, *report.medium])
    score += sum_weak(report.weak)
    if report.critical:
        # Critical evidence always decides the verdict on its own.
        score = max(score, 100)
    report.score = max(0, min(100, score))
    report.strong_signals = strong_count
    report.medium_signals = medium_count

    if report.critical:
        report.classification = MALICIOUS
        report.risk_level = CRITICAL_LEVEL
    elif strong_count > 0 or medium_count >= 2:
        report.classification, report.risk_level = _band_classification(
            report.score, strong_count, medium_count, thresholds or {}
        )
    else:
        report.classification = UNKNOWN
        report.risk_level = LOW
    report.confidence = _confidence_for(report)
    report.explanation = build_explanation(report)
    return report


def build_explanation(report: EvidenceReport) -> list[str]:
    """Turn correlated evidence into short, user-facing sentences."""
    explanation: list[str] = []
    for bucket in (report.critical, report.strong, report.medium):
        for item in bucket:
            if item.explanation and item.explanation not in explanation:
                explanation.append(item.explanation)
            if len(explanation) >= 6:
                return explanation
    if report.classification in (UNKNOWN, SAFE):
        if not explanation:
            explanation.append(
                "No threat-intelligence, impersonation, or URL-attack evidence was found."
            )
        for item in report.contextual:
            if item.explanation and item.explanation not in explanation:
                explanation.append(item.explanation)
            if len(explanation) >= 4:
                break
    return explanation
