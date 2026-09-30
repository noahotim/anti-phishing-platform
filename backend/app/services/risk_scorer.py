"""Risk scoring and classification.

Raw detection signals are first converted into structured evidence.  Weak
evidence can add a small amount of risk, but it cannot satisfy the evidence
gate: suspicion needs a strong signal or at least two independent medium
signals.  Related lexical findings share one capped group.

The default bands are:

  SAFE        score 0 and an exact trusted match
  UNKNOWN     0–20
  SUSPICIOUS  21–59, subject to the evidence gate
  HIGH_RISK   60–79
  MALICIOUS   80–100

``low``, ``moderate``, and ``high`` remain configurable as the UNKNOWN,
SUSPICIOUS, and HIGH_RISK ceilings.  Risk thresholds are stored
per-organization and configurable by admins.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import (
    CONTEXTUAL,
    CRITICAL,
    HIGH_RISK,
    LOW,
    MALICIOUS,
    MEDIUM,
    MODERATE,
    HIGH as HIGH_LEVEL_NAME,
    SAFE,
    STRONG,
    SUSPICIOUS,
    UNKNOWN,
    EvidenceItem,
    EvidenceReport,
    correlate_evidence,
)

LOW_LEVEL = LOW
MODERATE_LEVEL = MODERATE
HIGH_LEVEL = HIGH_LEVEL_NAME
CRITICAL_LEVEL = "CRITICAL"



@dataclass
class ScoreResult:
    score: int = 0
    classification: str = UNKNOWN
    risk_level: str = LOW
    reasons: list[str] = field(default_factory=list)
    matched_domain: str | None = None
    signals: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.0
    explanation: list[str] = field(default_factory=list)
    strong_signals: int = 0
    medium_signals: int = 0


def classify_raw(
    score: int,
    thresholds: dict[str, int],
    trusted_exact: bool,
    has_any_signal: bool,
    *,
    strong: bool = False,
    medium_count: int = 0,
) -> tuple[str, str]:
    """Map a score plus the evidence gate to a verdict.

    ``has_any_signal`` is retained for backward compatibility.  Weak signals
    alone no longer create suspicion: ``strong`` or at least two independent
    medium findings are required before a score above the UNKNOWN ceiling can
    become SUSPICIOUS.
    """
    low = int(thresholds.get("low", 20))
    suspicious_ceiling = int(thresholds.get("moderate", 59))
    high_ceiling = int(thresholds.get("high", 79))
    gated = bool(strong) or int(medium_count) >= 2

    if trusted_exact and score <= low:
        return SAFE, LOW
    if score <= low:
        return (SUSPICIOUS, MODERATE) if gated else (UNKNOWN, LOW)
    if score <= suspicious_ceiling:
        return SUSPICIOUS, MODERATE
    if score <= high_ceiling:
        return HIGH_RISK, HIGH_LEVEL_NAME
    return MALICIOUS, CRITICAL_LEVEL


def _legacy_items(signals: dict) -> tuple[list[EvidenceItem], str | None]:
    """Convert the historical signal dictionary into structured evidence."""
    flag = signals.get
    items: list[EvidenceItem] = []
    matched = flag("matched_domain")

    if flag("ti_malicious"):
        items.append(
            EvidenceItem(
                name="known_malicious",
                category=CRITICAL,
                weight=100,
                explanation="Confirmed malicious by threat intelligence.",
            )
        )
    if not flag("ti_benign") and not flag("trusted_exact"):
        items.append(
            EvidenceItem(
                name="unknown_domain",
                category="weak",
                weight=5,
                explanation="The domain is not in the trusted database.",
            )
        )
    if flag("confusable_exact_match"):
        items.append(
            EvidenceItem(
                name="confirmed_homograph",
                category=STRONG,
                weight=45,
                explanation=(
                    f"Domain visually matches approved domain \"{matched}\" "
                    "(confusable homoglyphs)."
                ),
                matched_domain=matched,
            )
        )
    edit_distance = int(flag("edit_distance", 0) or 0)
    character_ops = [str(op) for op in (flag("character_ops", []) or [])][:4]
    if 0 < edit_distance <= 2:
        explanation = (
            f"Domain differs by {edit_distance} character operation(s) from "
            f"approved \"{matched}\"."
        )
        if character_ops:
            explanation += " Character operations: " + "; ".join(character_ops) + "."
        items.append(
            EvidenceItem(
                name="very_close_typosquat",
                category=STRONG,
                weight=40,
                explanation=explanation,
                matched_domain=matched,
            )
        )
    elif 3 <= edit_distance <= 4:
        items.append(
            EvidenceItem(
                name="brand_similarity",
                category=MEDIUM,
                weight=25,
                explanation=(
                    f"Domain is lexically similar to approved \"{matched}\"."
                ),
                matched_domain=matched,
            )
        )
    if flag("punycode"):
        if flag("confusable_exact_match") or (matched and 0 < edit_distance <= 2):
            items.append(
                EvidenceItem(
                    name="punycode_impersonation",
                    category=STRONG,
                    weight=40,
                    explanation="Punycode encoding accompanies brand resemblance.",
                    matched_domain=matched,
                )
            )
        else:
            items.append(
                EvidenceItem(
                    name="punycode_marker",
                    category=CONTEXTUAL,
                    explanation="Domain uses IDN/Punycode encoding.",
                    matched_domain=matched,
                )
            )
    if flag("mixed_script"):
        if flag("confusable_exact_match") or (matched and 0 < edit_distance <= 2):
            items.append(
                EvidenceItem(
                    name="mixed_script",
                    category=MEDIUM,
                    weight=30,
                    explanation=f"Mixed Unicode script detected ({flag('mixed_script')}).",
                    matched_domain=matched,
                )
            )
        else:
            items.append(
                EvidenceItem(
                    name="mixed_script_marker",
                    category=CONTEXTUAL,
                    explanation=f"Mixed Unicode script note: {flag('mixed_script')}.",
                )
            )
    keywords = flag("keyword", [])
    if keywords:
        items.append(
            EvidenceItem(
                name="login_keyword",
                category="weak",
                weight=3,
                explanation=f"Keyword(s) in domain: {', '.join(keywords)}.",
                matched_domain=matched,
            )
        )
    if flag("brand_prefix"):
        items.append(
            EvidenceItem(
                name="brand_prefix",
                category=MEDIUM,
                weight=20,
                explanation=f"Approved brand \"{matched}\" is used with a prefix.",
                matched_domain=matched,
            )
        )
    if flag("brand_embedded"):
        items.append(
            EvidenceItem(
                name="brand_embedded",
                category=MEDIUM,
                weight=20,
                explanation="Approved brand name is embedded without a boundary.",
                matched_domain=matched,
            )
        )
    if flag("suffix_embedded"):
        items.append(
            EvidenceItem(
                name="brand_embedded",
                category=MEDIUM,
                weight=20,
                explanation="Approved domain appears as a suffix of this hostname.",
                matched_domain=matched,
            )
        )
    if flag("critical_impersonation"):
        items.append(
            EvidenceItem(
                name="critical_brand_match",
                category=MEDIUM,
                weight=15,
                explanation=f"Impersonates a brand marked CRITICAL: \"{matched}\".",
                matched_domain=matched,
            )
        )
    if flag("userinfo_present"):
        items.append(
            EvidenceItem(
                name="credential_userinfo",
                category=STRONG,
                weight=30,
                explanation="URL includes username/password components.",
            )
        )
    if flag("non_http_scheme"):
        items.append(
            EvidenceItem(
                name="non_http_scheme",
                category="weak",
                weight=3,
                explanation="Protocol is not http/https.",
            )
        )
    if flag("ip_host"):
        items.append(
            EvidenceItem(
                name="ip_host",
                category=CONTEXTUAL,
                explanation="Hostname is an IP address or local hostname.",
            )
        )
    if flag("tld_changed") or flag("tld_confusable"):
        items.append(
            EvidenceItem(
                name="tld_context",
                category=CONTEXTUAL,
                explanation="Any TLD difference from another domain is normal on its own.",
                matched_domain=matched,
            )
        )
    if flag("suspicious_tld"):
        items.append(
            EvidenceItem(
                name="suspicious_tld",
                category="weak",
                weight=5,
                explanation=f"Domain uses frequently-abused TLD \".{flag('suspicious_tld')}\".",
            )
        )
    if flag("redirect_param"):
        items.append(
            EvidenceItem(
                name="redirect_parameter",
                category="weak",
                weight=3,
                explanation="URL contains a redirect/open-redirect parameter.",
            )
        )
    if flag("brand_in_path"):
        items.append(
            EvidenceItem(
                name="brand_in_path",
                category=MEDIUM,
                weight=10,
                explanation="Approved brand name appears inside the URL path.",
                matched_domain=matched,
            )
        )
    return items, matched


def score_signals(signals: dict, thresholds: dict[str, int] | None = None) -> ScoreResult:
    """Compute a ScoreResult from historical signals through the new gate."""
    thresholds = thresholds or {}
    trusted_exact = bool(signals.get("trusted_exact"))
    if trusted_exact:
        return ScoreResult(
            score=0,
            classification=SAFE,
            risk_level=LOW,
            reasons=["Domain is an approved and trusted domain"],
            matched_domain=signals.get("matched_domain"),
            signals=signals,
            evidence={
                "critical": [],
                "strong": [],
                "medium": [],
                "weak": [],
                "contextual": ["trusted_domain"],
            },
            confidence=0.95,
            explanation=["Domain is an approved and trusted domain."],
        )

    items, matched = _legacy_items(signals or {})
    report: EvidenceReport = correlate_evidence(items, thresholds)
    classification, _ = classify_raw(
        report.score,
        thresholds,
        trusted_exact=False,
        has_any_signal=bool(items),
        strong=report.strong_signals > 0,
        medium_count=report.medium_signals,
    )
    # The report already applies the same gate; classification is copied here
    # so the legacy API stays consistent with the new engine.
    classification = report.classification
    return ScoreResult(
        score=report.score,
        classification=classification,
        risk_level=report.risk_level,
        reasons=list(report.explanation),
        matched_domain=matched,
        signals=signals,
        evidence=report.as_dict(),
        confidence=report.confidence,
        explanation=list(report.explanation),
        strong_signals=report.strong_signals,
        medium_signals=report.medium_signals,
    )
