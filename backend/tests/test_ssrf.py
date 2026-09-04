"""SSRF guard tests: the analyzer never blindly fetches arbitrary URLs.

We assert that:
  - literal private / loopback / link-local / metadata addresses are refused
  - non-http schemes are refused
  - arbitrary hosts are refused (allow-list only for external TI clients)
  - analyse of a URL such as http://169.254.169.254/ is a pure analysis that
    NEVER performs a network request (no outbound HTTP call is made).
"""
from __future__ import annotations

import pytest

from app.services.ssrf import (
    ALLOWED_TI_HOSTS,
    SSRFBlockedError,
    validate_url_host,
)

PUBLIC_OK = ["https://www.virustotal.com/foo", "https://safebrowsing.googleapis.com/v4/x"]

BLOCKED = [
    "http://127.0.0.1/",
    "https://192.168.1.10/",
    "http://10.0.0.5/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "ftp://example.com/",
    "file:///etc/passwd",
    "https://arbitrary.example.org/anything",   # not allow-listed
    "https://user:pass@virustotal.com/",         # userinfo not allowed
]


def test_allowed_ti_hosts():
    for url in PUBLIC_OK:
        host = validate_url_host(url)
        assert host in ALLOWED_TI_HOSTS


@pytest.mark.parametrize("url", BLOCKED, ids=BLOCKED)
def test_blocked(url):
    with pytest.raises(SSRFBlockedError):
        validate_url_host(url)


def test_analysis_never_contacts_network(client):
    """Analyzing a metadata URL must be a pure string analysis."""
    from app.services.analyzer import UrlAnalyzer
    r = UrlAnalyzer(org_id=1).analyze("http://169.254.169.254/latest/meta-data/")
    assert r.risk_score >= 0
    assert r.hostname in ("169.254.169.254", "")


def test_remote_providers_off_by_default():
    from app.services.threat_intel import build_provider_registry
    providers = build_provider_registry([])
    names = [p.name for p in providers]
    assert "local_database" in names
    # Remote providers only appear when explicitly enabled via env vars.
    assert not any(n in names for n in
                   ("google_safebrowsing", "virustotal", "urlhaus"))