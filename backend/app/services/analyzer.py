"""The analyzers: orchestrates URL/email analysis end to end.

Zero external I/O happens here unless an operator explicitly enables an
external threat-intel provider.  The analysis pipeline is:

  URL input
    → parse_url (authoritative host decomposition)
    → normalize_domain_identity / to_ascii / punycode flags
    → threat-intelligence provider verdicts
    → trusted-domain lookup (exact, allowed-subdomain aware)
    → brand/impersonation analysis against plausible trusted candidates
    → URL-attack analysis and structured evidence
    → evidence correlation, scoring, confidence, and explanations
    → persistence (url_scans + threat_intel_results)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from .. import database
from ..config import settings
from . import normalization
from .detection import build_detection_evidence
from .evidence import (
    HIGH_RISK,
    MALICIOUS,
    SAFE,
    SUSPICIOUS,
    UNKNOWN,
    correlate_evidence,
)
from .threat_intel import (
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_UNKNOWN,
    LocalThreatIntelProvider,
    ThreatIntelVerdict,
    build_provider_registry,
)
from .url_parser import parse_url, sanitize_url_for_logging, split_registered_domain

log = logging.getLogger("analyzer")


def _load_trusted(org_id: int) -> list[database.sqlite3.Row]:
    return database.fetchall(
        "SELECT * FROM trusted_domains WHERE org_id=? ORDER BY id", (org_id,)
    )


def _load_known_threats(org_id: int) -> list[dict]:
    return [
        dict(r)
        for r in database.fetchall(
            "SELECT domain, category FROM known_threats WHERE org_id=?", (org_id,)
        )
    ]


@dataclass
class AnalysisResult:
    url: str
    hostname: str = ""
    registered_domain: str = ""
    subdomain: str = ""
    ascii_domain: str = ""
    punycode_domain: str = ""
    is_ip: bool = False
    scheme: str = ""
    port: int | None = None
    username: str = ""
    password: str = ""
    tld: str = ""
    classification: str = UNKNOWN
    risk_score: int = 0
    risk_level: str = "LOW"
    confidence: float = 0.0
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    signals: dict = field(default_factory=dict)
    matched_domain: Optional[str] = None
    trusted: bool = False
    ti: list[dict] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "hostname": self.hostname,
            "registered_domain": self.registered_domain,
            "subdomain": self.subdomain,
            "ascii_domain": self.ascii_domain,
            "punycode_domain": self.punycode_domain,
            "is_ip": self.is_ip,
            "scheme": self.scheme,
            "port": self.port,
            "username": self.username,
            "password": "",
            "userinfo_present": bool(self.username or self.password),
            "tld": self.tld,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "blocked": self.blocked,
            "reasons": self.reasons,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "signals": self.signals,
            "matched_domain": self.matched_domain,
            "trusted": self.trusted,
            "threat_intel": self.ti,
            "details": self.details,
            "content_blocked": bool(self.signals.get("content_blocked")),
            "blocked_category": self.signals.get("blocked_category"),
            "safe_to_visit": self.classification == SAFE,
        }



def _check_allowed_subdomain(subdomain: str, allowed_rules: str) -> bool:
    """'*.company.com' style rules. Empty rule means exact host match only."""
    for rule in [r.strip().lower() for r in allowed_rules.split(",") if r.strip()]:
        if rule == "*.{domain}" or rule.startswith("*."):
            # Wildcard over everything below apex
            return True
        if rule.startswith("."):
            if subdomain.endswith(rule.rstrip(".")):
                return True
        elif subdomain and subdomain.endswith(rule):
            return True
    return False


class UrlAnalyzer:
    def __init__(
        self,
        org_id: int = 1,
        trusted_domains: list[dict] | None = None,
        providers: list | None = None,
        thresholds: dict[str, int] | None = None,
        persist: bool = True,
        user_id: Optional[int] = None,
    ) -> None:
        self.org_id = org_id
        self.thresholds = thresholds or database.Config.get_risk_thresholds(org_id)
        self.persist = persist
        self.user_id = user_id

        rows = trusted_domains
        if rows is None:
            rows = [dict(r) for r in _load_trusted(org_id)]
        self.trusted_rows: list[dict] = rows
        self.trusted_domains = [r["normalized_domain"] for r in self.trusted_rows]
        self.allowed = {
            r["normalized_domain"]: r.get("allowed_subdomains", "") or ""
            for r in self.trusted_rows
        }
        self.providers = providers
        # Policy-categorized entries (e.g. GAMBLING) are enforced in analyze()
        # and are NOT handed to the malware provider, so disabling the category
        # actually lifts the block. Uncategorized entries are always malware.
        self.policy_domains: dict[str, str] = {}
        self.blocked_categories: set[str] = set()
        if self.providers is None:
            known = _load_known_threats(org_id)
            malware = []
            for row in known:
                if row.get("category"):
                    host = (row["domain"] or "").lower().rstrip(".")
                    if host:
                        self.policy_domains.setdefault(host, row["category"])
                else:
                    malware.append(row["domain"])
            self.providers = build_provider_registry(malware)
            self.blocked_categories = set(
                database.Config.get_content_policy(org_id)
            ) | {"GAMBLING"}

    # ---- internal helpers -------------------------------------------------
    def _exact_trust_lookup(self, ascii_host: str, registered: str) -> Optional[dict]:
        host_s = ascii_host.strip().rstrip(".")
        apex = registered.strip().rstrip(".")
        for row in self.trusted_rows:
            t = row["normalized_domain"].rstrip(".")
            if host_s == t:
                return row
            # A subdomain of a trusted apex is trusted only when an explicit
            # allow-rule permits it.  This prevents trusted.com.attacker.com
            # style ownership confusion from bypassing detection.
            if apex == t and host_s.endswith("." + t):
                allowed = row.get("allowed_subdomains", "") or ""
                sub = host_s[: -(len(t) + 1)]
                if sub and allowed and _check_allowed_subdomain(sub, allowed):
                    return row
        return None

    # Betting keywords - always GAMBLING even if not in known_threats table
    _BETTING_KEYWORDS = ("bet", "casino", "poker", "slot", "gamble", "lotto", "wager", "pawa", "sportpesa", "1xbet", "betway", "betpawa")

    @staticmethod
    def _threat_intel_target(raw_url: str, host: str, password: str) -> str:
        """Host-safe URL for TI lookups and provider payloads."""
        if password and host:
            return f"https://{host}"
        if "@" in raw_url:
            return sanitize_url_for_logging(raw_url)
        return raw_url or (f"https://{host}" if host else "")

    def _policy_category(self, host: str, registered: str) -> Optional[str]:
        h = (host or "").lower().rstrip(".")
        registered = (registered or "").lower().rstrip(".")
        for bad, cat in self.policy_domains.items():
            bad = bad.lower().rstrip(".")
            bad_registered, _ = split_registered_domain(bad)
            target = bad_registered or bad
            # Compare registrable domains rather than using a bare suffix test.
            if h == bad or (registered and registered == target):
                return cat
        # Heuristic: any host containing betting keywords is GAMBLING - covers betpawa etc. even without DB entry
        if any(kw in h for kw in self._BETTING_KEYWORDS):
            return "GAMBLING"
        return None

    # ---- public entry -----------------------------------------------------
    def analyze(self, url: str, source: str = "EMPLOYEE") -> AnalysisResult:
        raw_url = (url or "").strip()
        parsed = parse_url(raw_url)
        if not parsed.hostname:
            # Treat a bare domain string as an https URL for friendliness.
            candidate = raw_url.lower()
            parsed = parse_url("https://" + candidate)
        host = parsed.ascii_host or ""
        registered = parsed.registered_domain or ""
        ascii_domain = normalization.to_ascii(parsed.hostname)

        # Exact trusted lookup.  Ownership is always established from the
        # registrable domain, including allowed-subdomain rules.
        matched = self._exact_trust_lookup(host, registered)
        trusted = matched is not None

        # ---- threat intelligence first (only local by default) ----
        ti_target = self._threat_intel_target(raw_url, host, parsed.password)
        ti_verdicts: list[ThreatIntelVerdict] = []
        for provider in self.providers:
            if not ti_target:
                break
            try:
                verdict = provider.check(ti_target)
            except Exception as exc:
                verdict = ThreatIntelVerdict(
                    provider=getattr(provider, "name", "unknown"),
                    verdict=VERDICT_UNKNOWN,
                    detail="provider error",
                    error=str(exc)[:300],
                )
            ti_verdicts.append(verdict)

        thresholds = self.thresholds or database.Config.get_risk_thresholds(self.org_id)
        detection = build_detection_evidence(
            parsed=parsed,
            raw_url=raw_url,
            trusted_rows=self.trusted_rows,
            trusted_match=matched,
            ti_verdicts=[v.to_dict() for v in ti_verdicts],
        )
        signals = detection.legacy_signals
        report = correlate_evidence(detection.items, thresholds)

        # Verified trust is positive evidence.  Confirmed threat intelligence
        # has already produced critical evidence and therefore overrides it.
        ti_malicious = any(v.verdict == VERDICT_MALICIOUS for v in ti_verdicts)
        ti_benign = bool(ti_verdicts) and all(
            v.verdict == VERDICT_BENIGN for v in ti_verdicts
        )
        if trusted and not ti_malicious:
            report.score = 0
            report.classification = SAFE
            report.risk_level = "LOW"
            report.confidence = 0.95
            report.explanation = ["Domain is an approved and trusted domain."]
        elif ti_benign and report.score <= 0 and report.classification == UNKNOWN:
            # A benign reputation finding is meaningful positive trust evidence.
            report.classification = SAFE
            report.risk_level = "LOW"
            report.confidence = max(report.confidence, 0.90)

        if report.classification in (SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN, HIGH_RISK):
            classification = report.classification
        else:
            classification = UNKNOWN

        # ---- content-policy enforcement (gambling / adult / social…) ----
        # Applies to all destinations (even trusted — so a trusted betting
        # domain is still blocked when its category is enabled). Admins
        # control categories via /api/settings/content-policy and the
        # Blocked-sites → Content policy UI.
        risk_level = report.risk_level
        risk_score = report.score
        blocked = classification in (HIGH_RISK, MALICIOUS)
        policy_reason = None
        policy_cat = self._policy_category(host, registered)
        # Trusted sites override content policy — user-added whitelist always wins
        if policy_cat and (policy_cat in self.blocked_categories or policy_cat == "GAMBLING") and not trusted:
            signals["content_blocked"] = True
            signals["blocked_category"] = policy_cat
            classification = MALICIOUS
            risk_score = 100
            risk_level = "CRITICAL"
            blocked = True
            policy_reason = (
                f"Blocked by organization policy — {policy_cat} "
                "websites are not allowed"
            )
        if policy_reason:
            report.explanation = list(report.explanation) + [policy_reason]

        # ---- whitelist-only mode (admin lockdown) ----
        # This is an explicit administrator lockdown: block every non-trusted
        # destination, including otherwise unknown-but-harmless sites.
        # Institutional context is not an exemption here.
        whitelist_reason = None
        if not trusted and not policy_reason:
            try:
                if database.Config.get_whitelist_only(self.org_id):
                    signals["whitelist_blocked"] = True
                    signals["content_blocked"] = True
                    signals["blocked_category"] = "WHITELIST"
                    classification = MALICIOUS
                    risk_score = 100
                    risk_level = "CRITICAL"
                    blocked = True
                    whitelist_reason = (
                        "Blocked by whitelist policy — only allowed sites can be visited. "
                        "Add this site to your allowed list to visit it."
                    )
            except Exception:
                pass
        if whitelist_reason:
            report.explanation = list(report.explanation) + [whitelist_reason]

        if classification in (SUSPICIOUS, HIGH_RISK, MALICIOUS):
            log.warning(
                "suspicious_url url=%s registrable_domain=%s classification=%s "
                "risk_score=%s confidence=%s strong=%s medium=%s weak=%s "
                "threat_intel=%s matched=%s timestamp=%s",
                sanitize_url_for_logging(raw_url),
                registered or host or "unknown",
                classification,
                risk_score,
                report.confidence,
                report.as_dict()["strong"],
                report.as_dict()["medium"],
                report.as_dict()["weak"],
                [v.provider for v in ti_verdicts if v.verdict == VERDICT_MALICIOUS],
                detection.matched_domain,
                database.utcnow_iso(),
            )

        result = AnalysisResult(
            url=raw_url,
            hostname=parsed.hostname,
            registered_domain=registered,
            subdomain=parsed.subdomain,
            ascii_domain=ascii_domain,
            punycode_domain=host if host.startswith("xn--") else "",
            is_ip=parsed.is_ip,
            scheme=parsed.scheme,
            port=parsed.port,
            username=parsed.username,
            password="",
            tld=parsed.tld,
            classification=classification,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=report.confidence,
            blocked=blocked,
            reasons=list(report.explanation),
            explanation=list(report.explanation),
            evidence=report.as_dict(),
            signals=signals,
            matched_domain=detection.matched_domain,
            trusted=trusted,
            ti=[v.to_dict() for v in ti_verdicts],
            details=parsed.as_dict(),
        )

        if self.persist:
            self._persist(result, ti_verdicts, source)
        return result

    def _persist(self, result: AnalysisResult, ti_verdicts: list[ThreatIntelVerdict],
                 source: str) -> int:
        stored_url = sanitize_url_for_logging(result.url)
        stored_details = dict(result.details or {})
        stored_details["raw"] = sanitize_url_for_logging(str(stored_details.get("raw", "")))
        scan_id = database.execute(
            """
            INSERT INTO url_scans
                (org_id, user_id, url, hostname, registered_domain,
                 punycode_domain, classification, risk_score, matched_domain,
                 signals, reasons, details, source, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                self.org_id,
                self.user_id,
                stored_url[:4000],
                result.hostname[:1024],
                result.registered_domain[:1023],
                result.punycode_domain[:1023],
                result.classification,
                result.risk_score,
                result.matched_domain,
                json.dumps(result.signals),
                json.dumps(result.reasons),
                json.dumps(stored_details),
                source,
                database.utcnow_iso(),
            ),
        )
        for v in ti_verdicts:
            payload = v.to_dict()
            payload["raw"] = {}
            database.execute(
                """
                INSERT INTO threat_intel_results
                    (url_scan_id, provider, verdict, score, payload, created_at)
                VALUES (?,?,?,?,?,?)
                """,
                (
                    scan_id,
                    v.provider,
                    v.verdict,
                    v.score,
                    json.dumps(payload),
                    database.utcnow_iso(),
                ),
            )
        return scan_id


def analyze_url_repository(org_id: int, url: str, source: str = "EMPLOYEE",
                           user_id: Optional[int] = None) -> AnalysisResult:
    return UrlAnalyzer(org_id=org_id, user_id=user_id).analyze(url, source=source)