"""Risk scoring and classification.

Turns raw signals into a single 0–100 score and one of SAFE / SUSPICIOUS /
MALICIOUS / UNKNOWN.  Classification is a monotonic function of the score band
(defaults below), which keeps the numbers honest on the warning page.

  SAFE        0–20   LOW
  SUSPICIOUS 21–50   MODERATE
  MALICIOUS  51–75   HIGH
  MALICIOUS  76–100  CRITICAL
  UNKNOWN    0       no evidence at all (not trusted, no signals, no intel)

Risk thresholds are stored per-organization and configurable by admins.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SAFE = "SAFE"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS = "MALICIOUS"
UNKNOWN = "UNKNOWN"

LOW = "LOW"
MODERATE = "MODERATE"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

_WEIGHTS = {
    "untrusted_destination": 8,       # baseline for not being approved
    "confusable_exact_match": 55,     # registered domain is a visual twin
    "edit_dist_1": 46,
    "edit_dist_2": 30,
    "edit_dist_3": 20,
    "edit_dist_4": 12,
    "tld_changed": 8,
    "tld_confusable": 12,
    "suspicious_tld": 15,
    "punycode": 12,
    "mixed_script": 14,
    "keyword": 9,
    "brand_embedded": 48,
    "brand_prefix": 26,
    "suffix_embedded": 24,
    "critical_impersonation": 15,
    "userinfo_present": 26,
    "non_http_scheme": 5,
    "ip_host": 26,
    "ti_malicious": 55,
    "redirect_param": 8,
    "brand_in_path": 10,
    "weak_tld": 6,
}


@dataclass
class ScoreResult:
    score: int = 0
    classification: str = UNKNOWN
    risk_level: str = LOW
    reasons: list[str] = field(default_factory=list)
    matched_domain: str | None = None
    signals: dict = field(default_factory=dict)


def classify_raw(
    score: int, thresholds: dict[str, int], trusted_exact: bool,
    has_any_signal: bool,
) -> tuple[str, str]:
    """Map score → (classification, risk_level).

    SAFE is reserved for exact approved matches and intel-verified benign
    domains.  An untrusted domain is never labelled SAFE: with zero evidence it
    is UNKNOWN, and with any suspicious signal it is SUSPICIOUS even when the
    numeric score stays low — safety first for employees.
    """
    if trusted_exact and score <= thresholds["low"]:
        return SAFE, LOW
    if score >= thresholds["high"] + 1:
        return MALICIOUS, CRITICAL if score >= 76 else HIGH
    if score > thresholds["moderate"]:
        return MALICIOUS, HIGH
    if score > thresholds["low"]:
        return SUSPICIOUS, MODERATE
    if score > 0:
        return (SUSPICIOUS, MODERATE) if has_any_signal else (UNKNOWN, LOW)
    return UNKNOWN, LOW


def score_signals(signals: dict, thresholds: dict[str, int] | None = None) -> ScoreResult:
    """Compute a ScoreResult from a signals dict produced by the analyzer."""
    total = 0
    reasons: list[str] = []
    weight = _WEIGHTS
    flag = signals.get

    def add(key: str, reason: str, cap: int = 100, times: int = 1) -> None:
        nonlocal total
        w = weight.get(key, 0)
        for _ in range(times):
            total += w
        total = min(cap, total)
        if reason:
            reasons.append(reason)

    trusted_exact = bool(flag("trusted_exact"))
    has_any = bool(
        flag("confusable_exact_match") == 1.0
        or flag("edit_distance", 0) > 0
        or flag("punycode")
        or flag("mixed_script")
        or flag("keyword", [])
        or flag("suspicious_tld")
        or flag("brand_embedded")
        or flag("brand_prefix")
        or flag("suffix_embedded")
        or flag("userinfo_present")
        or flag("ti_malicious")
        or flag("non_http_scheme")
        or flag("ip_host")
        or flag("tld_changed")
        or flag("redirect_param")
    )

    if trusted_exact:
        total = 0
        return ScoreResult(
            score=0,
            classification=SAFE,
            risk_level=LOW,
            reasons=["Domain is an approved and trusted domain"],
            matched_domain=flag("matched_domain"),
            signals=signals,
        )

    if flag("ti_malicious"):
        add("ti_malicious", "Confirmed malicious by threat intelligence", times=2)

    if not flag("ti_benign") and not trusted_exact:
        add("untrusted_destination", "Destination domain is not an approved domain")
        reasons[-1] = "Destination domain is not an approved domain"

    if flag("confusable_exact_match"):
        add(
            "confusable_exact_match",
            f"Domain visually matches approved domain "
            f"\"{flag('matched_domain')}\" (confusable homoglyphs)",
        )

    ed = flag("edit_distance", 0)
    trusted_label = flag("matched_domain")
    if 0 < ed <= 1:
        key = "edit_dist_1"
        add(key, f"Domain differs by {ed} character op(s) from approved \"{trusted_label}\"")
        if flag("character_ops"):
            for op in flag("character_ops")[:4]:
                reasons.append(f"- {op}")
    elif ed == 2:
        add("edit_dist_2", f"Domain differs by two characters from \"{trusted_label}\"")
    elif ed == 3:
        add("edit_dist_3", f"Domain differs by three characters from \"{trusted_label}\"")
    elif ed == 4:
        add("edit_dist_4", f"Domain differs by four characters from \"{trusted_label}\"")

    if flag("punycode"):
        add("punycode", "Domain uses IDN/Punycode encoding")
    if flag("mixed_script"):
        add("mixed_script", f"Mixed Unicode script detected ({flag('mixed_script')})")
    kws = flag("keyword", [])
    if kws:
        add("keyword", f"Suspicious keyword(s) in domain: {', '.join(kws)}",
            times=min(2, len(kws)))

    if flag("brand_embedded"):
        add("brand_embedded", "Approved brand name embedded as subdomain or prefix")
    if flag("brand_prefix"):
        add("brand_prefix",
            f"Approved brand \"{trusted_label}\" used with a look-alike prefix")
    if flag("suffix_embedded"):
        add("suffix_embedded", "Approved domain appears as a suffix of this hostname")
    if flag("critical_impersonation"):
        add("critical_impersonation",
            f"Impersonates a brand marked CRITICAL: \"{trusted_label}\"")

    if flag("userinfo_present"):
        add("userinfo_present", "URL includes username/password components")
    if flag("non_http_scheme"):
        add("non_http_scheme", "Protocol is not http/https")
    if flag("ip_host"):
        add("ip_host", "Hostname is an IP address or local hostname")
    if flag("tld_changed") and not trusted_exact:
        add("tld_changed", "Top-level domain differs from approved domain")
    if flag("tld_confusable"):
        add("tld_confusable", flag("tld_confusable"))
    if flag("suspicious_tld"):
        add("suspicious_tld", f"Domain uses frequently-abused TLD \".{flag('suspicious_tld')}\"")
    if flag("redirect_param"):
        add("redirect_param", "URL contains a redirect/open-redirect parameter")
    if flag("brand_in_path"):
        add("brand_in_path", "Approved brand name appears inside the URL path")

    total = min(100, total)
    classification, risk_level = classify_raw(
        total, thresholds or {}, trusted_exact, has_any
    )
    return ScoreResult(
        score=total,
        classification=classification,
        risk_level=risk_level,
        reasons=reasons,
        matched_domain=flag("matched_domain"),
        signals=signals,
    )