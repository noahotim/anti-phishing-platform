"""Threat intelligence providers.

The local engine is the source of truth and continues working with no external
dependency.  External providers (Google Safe Browsing, VirusTotal, URLhaus) are
pluggable behind a common interface; they are disabled unless the operator
configures API keys AND sets ENABLE_EXTERNAL_TI=true.  All outbound calls are
routed through the SSRF guard's fixed allow-list.
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..config import settings
from .ssrf import SSRFBlockedError, validate_url_host

log = logging.getLogger("ti")

VERDICT_UNKNOWN = "UNKNOWN"
VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_BENIGN = "BENIGN"


@dataclass
class ThreatIntelVerdict:
    provider: str
    verdict: str = VERDICT_UNKNOWN
    score: int = 0            # 0 unknown, 0-100 malicious severity
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "verdict": self.verdict,
            "score": self.score,
            "detail": self.detail,
            "raw": self.raw,
            "error": self.error,
        }


class ThreatIntelligenceProvider(ABC):
    name = "base"

    @abstractmethod
    def check(self, url: str) -> ThreatIntelVerdict: ...


class LocalThreatIntelProvider(ThreatIntelligenceProvider):
    """Checks the organization's local known_threats table (zero network).

    `known_bad_domains` is injected by the analyzer with rows from DB so the
    provider stays a pure function and remains easily unit-testable.
    """

    name = "local_database"

    def __init__(self, known_bad_domains: list[str]) -> None:
        self.known_bad = {d.lower().rstrip(".") for d in known_bad_domains}

    def check(self, url: str) -> ThreatIntelVerdict:
        from .url_parser import parse_url

        parsed = parse_url(url)
        host = parsed.ascii_host
        for bad in self.known_bad:
            if bad and (host == bad or (len(bad) > 3 and host.endswith("." + bad))):
                return ThreatIntelVerdict(
                    provider=self.name,
                    verdict=VERDICT_MALICIOUS,
                    score=95,
                    detail=f"Domain '{host}' matches known malicious domain '{bad}'",
                )
        return ThreatIntelVerdict(
            provider=self.name,
            verdict=VERDICT_UNKNOWN,
            score=0,
            detail="no local threat-intel match",
        )


class _SSRFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect hop against the SSRF policy."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        validate_url_host(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _SafeHTTPClient:
    """Tiny outbound client that honours the SSRF policy for fixed API hosts."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_SSRFRedirectHandler)

    def get_json(self, url: str, headers: dict | None = None) -> Any:
        validate_url_host(url)
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        with self.opener.open(req, timeout=self.timeout) as resp:
            if resp.status != 200:
                raise RuntimeError(f"http {resp.status}")
            body = resp.read(500_000)
            return json.loads(body.decode("utf-8"))

    def get_text(
        self, url: str, headers: dict | None = None, max_bytes: int = 30_000_000,
    ) -> str:
        validate_url_host(url)
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        with self.opener.open(req, timeout=self.timeout) as resp:
            if resp.status != 200:
                raise RuntimeError(f"http {resp.status}")
            return resp.read(max_bytes).decode("utf-8", errors="replace")

    def post_json(self, url: str, payload: dict, headers: dict | None = None) -> Any:
        validate_url_host(url)
        data = json.dumps(payload).encode("utf-8")
        hdrs = {"Content-Type": "application/json", "User-Agent": "antiphishing/1.0"}
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        with self.opener.open(req, timeout=self.timeout) as resp:
            if resp.status != 200:
                raise RuntimeError(f"http {resp.status}")
            body = resp.read(500_000)
            return json.loads(body.decode("utf-8"))


class GoogleSafeBrowsingProvider(ThreatIntelligenceProvider):
    name = "google_safebrowsing"

    def __init__(self, api_key: str, client_id: str, base_url: str, timeout: float) -> None:
        self.api_key = api_key
        self.client_id = client_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http = _SafeHTTPClient(timeout)

    def check(self, url: str) -> ThreatIntelVerdict:
        from urllib.parse import urlsplit

        try:
            host = urlsplit(url).hostname
            endpoint = f"{self.base_url}/threatMatches:find?key={self.api_key}"
            payload = {
                "client": {"clientId": self.client_id, "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url[:2048]}],
                },
            }
            data = self._http.post_json(endpoint, payload)
            matches = data.get("matches", [])
            if matches:
                return ThreatIntelVerdict(
                    provider=self.name,
                    verdict=VERDICT_MALICIOUS,
                    score=90,
                    detail=f"Google Safe Browsing flagged URL: {matches}",
                    raw=data,
                )
            return ThreatIntelVerdict(
                provider=self.name,
                verdict=VERDICT_BENIGN,
                score=0,
                detail="no Google Safe Browsing match",
                raw=data,
            )
        except (urllib.error.URLError, TimeoutError, SSRFBlockedError, ValueError) as exc:
            return ThreatIntelVerdict(
                provider=self.name,
                verdict=VERDICT_UNKNOWN,
                detail="provider unavailable",
                error=str(exc)[:300],
            )
        except Exception as exc:  # never let a provider take down the scanner
            return ThreatIntelVerdict(
                provider=self.name, verdict=VERDICT_UNKNOWN,
                detail="provider error", error=str(exc)[:300],
            )


class VirusTotalProvider(ThreatIntelligenceProvider):
    name = "virustotal"

    def __init__(self, api_key: str, base_url: str, timeout: float) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http = _SafeHTTPClient(timeout)

    def check(self, url: str) -> ThreatIntelVerdict:
        import hashlib

        url_hash = hashlib.sha256(
            (url or "").encode("utf-8")
        ).hexdigest()
        try:
            data = self._http.get_json(
                f"{self.base_url}/urls/{url_hash}",
                headers={"x-apikey": self.api_key},
            )
            return self._verdict_from(data)
        except Exception as exc:
            return ThreatIntelVerdict(
                provider=self.name,
                verdict=VERDICT_UNKNOWN,
                detail="provider unavailable",
                error=str(exc)[:300],
            )

    def _verdict_from(self, data: dict) -> ThreatIntelVerdict:
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            if malicious > 0:
                return ThreatIntelVerdict(
                    provider=self.name, verdict=VERDICT_MALICIOUS,
                    score=min(100, 60 + malicious * 5),
                    detail=f"VirusTotal {malicious} malicious verdicts",
                    raw=data,
                )
            return ThreatIntelVerdict(
                provider=self.name, verdict=VERDICT_BENIGN,
                score=0, detail="no VirusTotal detections", raw=data,
            )
        except Exception as exc:
            return ThreatIntelVerdict(
                provider=self.name, verdict=VERDICT_UNKNOWN,
                detail="provider parse error", error=str(exc)[:300],
            )


class URLhausProvider(ThreatIntelligenceProvider):
    name = "urlhaus"

    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http = _SafeHTTPClient(timeout)

    def check(self, url: str) -> ThreatIntelVerdict:
        try:
            data = self._http.post_json(
                f"{self.base_url}/url/",
                {"url": url[:2048]},
                headers={"User-Agent": "antiphishing-platform"},
            )
            if data.get("query_status") == "ok" and data.get("url_status") == "online":
                return ThreatIntelVerdict(
                    provider=self.name, verdict=VERDICT_MALICIOUS,
                    score=90, detail=data.get("urlhaus_reference", ""), raw=data,
                )
            return ThreatIntelVerdict(
                provider=self.name, verdict=VERDICT_UNKNOWN,
                detail="no URLhaus hit", raw=data,
            )
        except Exception as exc:
            return ThreatIntelVerdict(
                provider=self.name, verdict=VERDICT_UNKNOWN,
                detail="provider unavailable", error=str(exc)[:300],
            )


def _parse_hostfile(text: str, max_items: int = 5000) -> list[str]:
    """Parse abuse.ch URLhaus hostfile lines into a de-duplicated host list.

    Format (one per line):  `0.0.0.0 <host>` or `127.0.0.1 <host>`.
    """
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0] in {"0.0.0.0", "127.0.0.1"}:
            host = parts[1].strip().lower().rstrip(".")
            if host and not host.startswith(".") and host not in seen:
                seen.add(host)
                out.append(host)
                if len(out) >= max_items:
                    break
    return out


def fetch_urlhaus_hostfile(max_items: int = 5000) -> list[str]:
    """Download the public URLhaus malicious-host feed (no API key needed)."""
    endpoint = "https://urlhaus.abuse.ch/downloads/hostfile/"
    http = _SafeHTTPClient(settings.ti_fetch_timeout_s)
    text = http.get_text(endpoint, headers={"User-Agent": "antiphishing-platform"})
    return _parse_hostfile(text, max_items)


def build_provider_registry(
    known_bad_domains: list[str] | None = None,
) -> list[ThreatIntelligenceProvider]:
    """Build the active provider list honouring settings.

    Local provider is always active.  Remote providers are registered only when
    explicitly enabled via ENABLE_EXTERNAL_TI + the provider API key.
    """
    providers: list[ThreatIntelligenceProvider] = [
        LocalThreatIntelProvider(known_bad_domains or [])
    ]
    if settings.enable_external_ti:
        if settings.google_safebrowsing_api_key:
            providers.append(
                GoogleSafeBrowsingProvider(
                    settings.google_safebrowsing_api_key,
                    settings.google_safebrowsing_client_id,
                    settings.google_safebrowsing_base_url,
                    settings.ti_fetch_timeout_s,
                )
            )
        if settings.virustotal_api_key:
            providers.append(
                VirusTotalProvider(
                    settings.virustotal_api_key,
                    settings.virustotal_base_url,
                    settings.ti_fetch_timeout_s,
                )
            )
        providers.append(
            URLhausProvider(settings.urlhaus_base_url, settings.ti_fetch_timeout_s)
        )
    return providers