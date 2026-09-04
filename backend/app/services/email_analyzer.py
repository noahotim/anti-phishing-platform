"""Email phishing analysis service.

Stateless analysis of an email's sender, reply-to, displayed links vs actual
URLs, subject/body keywords, attachment metadata, and sender-domain
impersonation against the organization's trusted domain set.  This is purely
analytical — no sending, deleting, or quarantining happens anywhere.  Any
future destructive action MUST be gated behind explicit administrator
configuration (per requirements §11).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Any, Optional

from .analyzer import UrlAnalyzer
from .risk_scorer import MALICIOUS, SAFE, SUSPICIOUS, UNKNOWN
from .similarity import SimilarityEngine
from .url_parser import parse_url


@dataclass
class LinkFinding:
    display_text: str = ""
    url: str = ""
    hostname: str = ""
    risk_score: int = 0
    classification: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "display_text": self.display_text,
            "url": self.url,
            "hostname": self.hostname,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "reasons": self.reasons,
        }


@dataclass
class EmailAnalysis:
    provider_header_from: str = ""
    sender_address: str = ""
    sender_domain: str = ""
    reply_to_address: str = ""
    reply_to_domain: str = ""
    subject: str = ""
    impersonates: Optional[str] = None
    sender_fold_match: bool = False
    keyword_hits: list[str] = field(default_factory=list)
    display_mismatches: list[LinkFinding] = field(default_factory=list)
    link_findings: list[LinkFinding] = field(default_factory=list)
    attachment_risks: list[str] = field(default_factory=list)
    classification: str = UNKNOWN
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "provider_header_from": self.provider_header_from,
            "sender_address": self.sender_address,
            "sender_domain": self.sender_domain,
            "reply_to_address": self.reply_to_address,
            "reply_to_domain": self.reply_to_domain,
            "subject": self.subject,
            "impersonates": self.impersonates,
            "sender_fold_match": self.sender_fold_match,
            "keyword_hits": self.keyword_hits,
            "display_mismatches": [l.to_dict() for l in self.display_mismatches],
            "link_findings": [l.to_dict() for l in self.link_findings],
            "attachment_risks": self.attachment_risks,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
        }


class EmailAnalyzer:
    def __init__(
        self,
        org_id: int = 1,
        trusted_domains: list[str] | list[dict] | None = None,
        keywords: tuple[str, ...] | None = None,
        url_analyzer: UrlAnalyzer | None = None,
    ) -> None:
        self.org_id = org_id
        self.keywords = keywords or tuple(
            k.lower() for k in (
                "verify", "verification", "confirm", "password", "credential",
                "invoice", "payment", "urgent", "suspended", "locked", "security",
                "account", "update", "wallet", "refund", "wire", "lottery",
                "gift card", "bonus", "irs", "tax refund", "login",
            )
        )
        self.url_analyzer = url_analyzer or UrlAnalyzer(org_id=org_id, persist=False)
        if isinstance(trusted_domains, list) and trusted_domains and isinstance(
            trusted_domains[0], dict
        ):
            self.trusted_domains = [d["normalized_domain"] for d in trusted_domains]
        else:
            self.trusted_domains = (
                list(self.url_analyzer.trusted_domains)
                if trusted_domains is None else list(trusted_domains)
            )
        self.similarity = SimilarityEngine(self.trusted_domains)

    # ------------------------------------------------------------------
    def analyze_email(
        self,
        *,
        from_header: str,
        reply_to: str = "",
        subject: str = "",
        body: str = "",
        links: list[dict] | None = None,
        attachments: list[dict] | None = None,
    ) -> EmailAnalysis:
        result = EmailAnalysis()
        result.subject = subject or ""
        # parse the header and extract just the address
        _disp, sender = parseaddr(from_header or "")
        result.provider_header_from = from_header or ""
        result.sender_address = sender.lower()
        result.sender_domain = self._domain_of(result.sender_address)
        if reply_to:
            _, rt = parseaddr(reply_to)
            result.reply_to_address = rt.lower()
            result.reply_to_domain = self._domain_of(rt)

        # ---- sender-domain impersonation ----------------------------------
        finding = self.similarity.best_finding(result.sender_domain)
        if (
            finding
            and result.sender_domain not in self.trusted_domains
        ):
            if finding.fold_match or finding.edit_distance <= 2:
                result.impersonates = finding.trusted_domain
                result.sender_fold_match = finding.fold_match
                result.reasons.append(
                    f"Sender domain '{result.sender_domain}' resembles approved "
                    f"domain '{finding.trusted_domain}'"
                )
            if finding.fold_match:
                result.reasons.append("Sender domain uses confusable homoglyphs")
            for op in finding.char_ops[:3]:
                result.reasons.append(f"- {op}")
            result.risk_score += 45

        # reply-to domain different from trusted sender
        if result.reply_to_domain and result.reply_to_domain != result.sender_domain:
            rev = self.similarity.best_finding(result.reply_to_domain)
            if rev and rev.edit_distance <= 2 and result.reply_to_domain not in self.trusted_domains:
                result.reasons.append(
                    f"Reply-to domain '{result.reply_to_domain}' resembles approved "
                    f"domain '{rev.trusted_domain}'"
                )
                result.risk_score += 35

        # ---- keywords -------------------------------------------------------
        haystack = f"{subject} {body}".lower()
        hits = [k for k in self.keywords if k in haystack]
        result.keyword_hits = hits[:6]
        if hits:
            result.risk_score += min(20, 6 * len(hits))
            result.reasons.append(
                "Suspicious keyword(s) present: " + ", ".join(hits[:4])
            )

        # ---- links ----------------------------------------------------------
        for link in links or []:
            text = (link.get("text") or "").strip()
            href = (link.get("href") or "").strip()
            lf = self._analyze_link(text, href)
            if lf.display_text and lf.url and lf.hostname != lf.display_text:
                # display text vs actual hostname mismatch
                lf2 = LinkFinding(
                    display_text=text,
                    url=href,
                    hostname=lf.hostname,
                    risk_score=lf.risk_score,
                    classification=lf.classification,
                    reasons=["Display text does not match the destination hostname"],
                )
                if lf.reasons:
                    lf2.reasons.extend(lf.reasons)
                result.display_mismatches.append(lf2)
                result.risk_score += 25
                result.reasons.append(
                    f"Link text \"{text[:60]}\" points to different host '{lf.hostname}'"
                )
            else:
                result.display_mismatches.append(lf)
            result.link_findings.append(lf)
            if lf.classification == MALICIOUS:
                result.risk_score += 30
                result.reasons.append(f"Link to malicious destination: {href[:80]}")
            elif lf.classification == SUSPICIOUS:
                result.risk_score += 15
                result.reasons.append(f"Link to suspicious destination: {href[:80]}")

        # ---- attachments ------------------------------------------------------
        for att in attachments or []:
            name = (att.get("filename") or "").lower()
            mime = (att.get("mime_type") or "").lower()
            risk_names = (".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".docm", ".xlsm")
            if name.endswith(risk_names) or "script" in mime:
                result.attachment_risks.append(name or mime or "unknown")
                result.risk_score += 20
                result.reasons.append(f"High-risk attachment type: {name or mime}")

        if result.risk_score > 0:
            result.classification = (
                MALICIOUS if result.risk_score >= 51
                else SUSPICIOUS if result.risk_score >= 21
                else SAFE
            )
        else:
            result.classification = SAFE
        result.risk_score = min(100, result.risk_score)
        return result

    def _domain_of(self, address: str) -> str:
        if "@" in address:
            return address.rsplit("@", 1)[1].strip().rstrip(".").lower()
        return (address or "").rstrip(".").lower()

    def _analyze_link(self, text: str, href: str) -> LinkFinding:
        if not href:
            return LinkFinding(display_text=text, url="", hostname="")
        parsed = parse_url(href)
        host = parsed.ascii_host or parsed.hostname or ""
        finding = LinkFinding(display_text=text, url=href, hostname=host)
        if not host:
            finding.reasons.append("No valid hostname in link")
            return finding
        try:
            analyzed = self.url_analyzer.analyze(href, source="EMAIL")
        except Exception:
            analyzed = None
        if analyzed:
            finding.risk_score = analyzed.risk_score
            finding.classification = analyzed.classification
            finding.reasons = list(analyzed.reasons)
        return finding