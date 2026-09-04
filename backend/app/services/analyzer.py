"""The analyzers: orchestrates URL/email analysis end to end.

Zero external I/O happens here unless an operator explicitly enables an
external threat-intel provider.  The analysis pipeline is:

  URL input
    → parse_url (authoritative host decomposition)
    → normalize_domain_identity / to_ascii / punycode flags
    → trusted-domain lookup (exact, allowed-subdomain aware)
    → confusable & similarity analysis against the trusted set
    → signal assembly
    → risk scoring → classification → reasons
    → threat-intel enrichment (provider registry)
    → persistence (url_scans + threat_intel_results)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .. import database
from ..config import settings
from . import normalization
from .public_suffix import PUBLIC_SUFFIXES
from .risk_scorer import MALICIOUS, SAFE, SUSPICIOUS, UNKNOWN, score_signals
from .similarity import SimilarityEngine, SUSPICIOUS_TLDS, keyword_hits
from .threat_intel import (
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_UNKNOWN,
    LocalThreatIntelProvider,
    ThreatIntelVerdict,
    build_provider_registry,
)
from .url_parser import parse_url

log = logging.getLogger("analyzer")

_REDIRECT_PARAMS = ("redirect", "redirect_url", "redirecturi", "url", "next", "returnurl")

_ALLOWED_SUB_RX = re.compile(r"^(\*\.)?[a-z0-9.-]+$")


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
    reasons: list[str] = field(default_factory=list)
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
            "password": self.password,
            "tld": self.tld,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "signals": self.signals,
            "matched_domain": self.matched_domain,
            "trusted": self.trusted,
            "threat_intel": self.ti,
            "details": self.details,
            "content_blocked": bool(self.signals.get("content_blocked")),
            "blocked_category": self.signals.get("blocked_category"),
            "safe_to_visit": self.classification == SAFE and not self._caveat(),
        }

    def _caveat(self) -> bool:
        return bool(self.signals.get("untrusted_destination")) and \
            self.classification == SAFE


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
        self.similarity = SimilarityEngine(self.trusted_domains)
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
            )

    # ---- internal helpers -------------------------------------------------
    def _exact_trust_lookup(self, ascii_host: str, registered: str) -> Optional[dict]:
        host_s = ascii_host.strip().rstrip(".")
        apex = registered.strip().rstrip(".")
        for row in self.trusted_rows:
            t = row["normalized_domain"].rstrip(".")
            if host_s == t:
                return row
            if apex == t:
                allowed = row.get("allowed_subdomains", "") or ""
                sub = host_s[: -(len(t) + 1)] if host_s.endswith("." + t) else ""
                if sub and allowed and not _check_allowed_subdomain(sub, allowed):
                    # Subdomains are restricted by an explicit allow-rule and
                    # this one does not match it.
                    return None
                return row
        return None

    def _policy_category(self, host: str) -> Optional[str]:
        h = (host or "").lower().rstrip(".")
        for bad, cat in self.policy_domains.items():
            if h == bad or (len(bad) > 3 and h.endswith("." + bad)):
                return cat
        return None

    # ---- public entry -----------------------------------------------------
    def analyze(self, url: str, source: str = "EMPLOYEE") -> AnalysisResult:
        parsed = parse_url(url or "")
        if not parsed.hostname:
            # Treat a bare domain string as an https URL for friendliness.
            candidate = (url or "").strip().lower()
            parsed = parse_url("https://" + candidate)
        host = parsed.ascii_host or ""
        registered = parsed.registered_domain or ""
        ascii_domain = normalization.to_ascii(parsed.hostname)

        # exact trusted lookup
        matched = self._exact_trust_lookup(host, registered)
        trusted = matched is not None
        punycode_flag = host.startswith("xn--") or normalization.to_ascii(
            parsed.hostname
        ).startswith("xn--")

        signals: dict[str, Any] = {
            "exact_match": trusted,
            "trusted_domain": trusted,
            "trusted_exact": trusted,
            "matched_domain": matched["normalized_domain"] if matched else None,
            "hostname": host,
            "registered_domain": registered,
        }

        finding = None if trusted else self.similarity.best_finding(host or registered or url)

        # ---- character / structural signals ----
        if finding:
            if finding.edit_distance <= 4 or finding.fold_match:
                signals["edit_distance"] = finding.edit_distance
                signals["matched_domain"] = finding.trusted_domain
            if finding.fold_match:
                signals["confusable_exact_match"] = True
                signals["matched_domain"] = finding.trusted_domain
                if signals.get("edit_distance", 99) > 2:
                    signals["edit_distance"] = 2
            if finding.char_ops:
                signals["character_ops"] = list(dict.fromkeys(finding.char_ops))
            if finding.keyword_hits:
                signals["keyword"] = finding.keyword_hits
            if finding.punycode or punycode_flag:
                signals["punycode"] = True
                unicode_form = normalization.to_unicode(host)
                if unicode_form and unicode_form != host:
                    from .homoglyph import mixed_script_warning
                    warning = mixed_script_warning(unicode_form)
                    if warning:
                        signals["mixed_script"] = warning
            if finding.mixed_script:
                signals["mixed_script"] = finding.mixed_script
            if finding.misleading_subdomain:
                signals["brand_embedded"] = True
                signals["matched_domain"] = finding.trusted_domain
            if finding.brand_prefix:
                signals["brand_prefix"] = True
                signals["matched_domain"] = finding.trusted_domain
            if finding.suffix_embedded:
                signals["suffix_embedded"] = True
                signals["matched_domain"] = finding.trusted_domain
            if finding.same_tld is False:
                signals["tld_changed"] = True
            if finding.tld_confusion:
                signals["tld_confusable"] = finding.tld_confusion
            if finding.suspicious_tld:
                signals["suspicious_tld"] = finding.suspicious_tld
            # impersonation of a critical brand is weighted harder
            if signals.get("matched_domain"):
                for row in self.trusted_rows:
                    if row["normalized_domain"] == signals["matched_domain"] \
                            and row["is_critical"]:
                        signals["critical_impersonation"] = True
                        break

        if parsed.username:
            signals["userinfo_present"] = True
        if parsed.scheme not in ("http", "https"):
            signals["non_http_scheme"] = True
        if parsed.is_ip:
            signals["ip_host"] = True
        if not trusted:
            signals["untrusted_destination"] = True

        # path-based brand deception: /company.com/ or /trusted-login/
        if finding and finding.trusted_domain:
            brand = finding.trusted_domain.split(".")[0]
            if re.search(rf"(?i)(/|\b){re.escape(brand)}(\b|/)", parsed.path):
                signals["brand_in_path"] = True

        # redirect params
        qk = [k.lower() for k in re.findall(r"([^&=]+)=", parsed.query)]
        if any(k in _REDIRECT_PARAMS for k in qk):
            signals["redirect_param"] = True

        # ---- threat intelligence (only local by default) ----
        ti_verdicts: list[ThreatIntelVerdict] = []
        for provider in self.providers:
            try:
                verdict = provider.check(url or f"https://{host}")
            except Exception as exc:
                verdict = ThreatIntelVerdict(
                    provider=getattr(provider, "name", "unknown"),
                    verdict=VERDICT_UNKNOWN,
                    detail="provider error",
                    error=str(exc)[:300],
                )
            ti_verdicts.append(verdict)
            if verdict.verdict == VERDICT_MALICIOUS:
                signals["ti_malicious"] = True
            if verdict.verdict == VERDICT_BENIGN:
                signals["ti_benign"] = True

        thresholds = self.thresholds or database.Config.get_risk_thresholds(self.org_id)
        scored = score_signals(signals, thresholds)

        if scored.classification in (SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN):
            classification = scored.classification
        else:
            classification = UNKNOWN

        # If TI benign and not otherwise risky → safe
        if signals.get("ti_benign") and scored.score <= 0:
            classification = SAFE

        # ---- content-policy enforcement (gambling / adult / social…) ----
        # Categorized known_threats rows only block when their category is
        # active in the org content policy, so admins can lift a category.
        risk_level = scored.risk_level
        risk_score = scored.score
        policy_reason = None
        if not trusted:
            policy_cat = self._policy_category(host)
            if policy_cat and policy_cat in self.blocked_categories:
                signals["content_blocked"] = True
                signals["blocked_category"] = policy_cat
                classification = MALICIOUS
                risk_score = 100
                risk_level = "CRITICAL"
                policy_reason = (
                    f"Blocked by organization policy — {policy_cat} "
                    "websites are not allowed"
                )
        if policy_reason:
            scored.reasons = list(scored.reasons) + [policy_reason]

        # ---- whitelist-only mode (admin lockdown) ----
        # When enabled, every non-trusted destination is blocked.
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
                    whitelist_reason = (
                        "Blocked by whitelist policy — only allowed sites can be visited. "
                        "Add this site to your allowed list to visit it."
                    )
            except Exception:
                pass
        if whitelist_reason:
            scored.reasons = list(scored.reasons) + [whitelist_reason]

        result = AnalysisResult(
            url=url.strip(),
            hostname=parsed.hostname,
            registered_domain=registered,
            subdomain=parsed.subdomain,
            ascii_domain=ascii_domain,
            punycode_domain=host if host.startswith("xn--") else "",
            is_ip=parsed.is_ip,
            scheme=parsed.scheme,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            tld=registered.rsplit(".", 1)[-1] if "." in registered else "",
            classification=classification,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=scored.reasons,
            signals=signals,
            matched_domain=scored.matched_domain,
            trusted=trusted,
            ti=[v.to_dict() for v in ti_verdicts],
            details=parsed.as_dict(),
        )

        if self.persist:
            self._persist(result, ti_verdicts, source)
        return result

    def _persist(self, result: AnalysisResult, ti_verdicts: list[ThreatIntelVerdict],
                 source: str) -> int:
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
                result.url[:4000],
                result.hostname[:1024],
                result.registered_domain[:1023],
                result.punycode_domain[:1023],
                result.classification,
                result.risk_score,
                result.matched_domain,
                json.dumps(result.signals),
                json.dumps(result.reasons),
                json.dumps(result.details),
                source,
                database.utcnow_iso(),
            ),
        )
        for v in ti_verdicts:
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
                    json.dumps(v.to_dict()),
                    database.utcnow_iso(),
                ),
            )
        return scan_id


def analyze_url_repository(org_id: int, url: str, source: str = "EMPLOYEE",
                           user_id: Optional[int] = None) -> AnalysisResult:
    return UrlAnalyzer(org_id=org_id, user_id=user_id).analyze(url, source=source)