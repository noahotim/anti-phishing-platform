"""End-to-end analyzer tests over a safe/suspicious/malicious dataset."""
from __future__ import annotations

import pytest

from app.services.analyzer import UrlAnalyzer

# (url, expected classification list, expected matched brand or None)
# Multiple allowed classifications are for band-parameterized expectations.
DATASET = [
    # --- safe: exact trusted domains / legitimate subdomains ---
    ("https://maybank2u.com/", "SAFE", "maybank2u.com"),
    ("https://www.google.com/", "SAFE", "google.com"),
    ("https://mail.google.com/", "SAFE", "google.com"),
    ("https://www.microsoft.com/", "SAFE", "microsoft.com"),
    ("https://company-example.com/dashboard", "SAFE", "company-example.com"),
    # --- typosquatting / substitution / insertion / deletion ---
    ("https://examp1e.com/login", "MALICIOUS", "example.com"),   # 1->e (fold)
    ("https://exampple.com/", "MALICIOUS", "example.com"),       # insertion
    ("https://exampl.com/", "MALICIOUS", "example.com"),         # deletion
    ("https://exampel.com/", "MALICIOUS", "example.com"),        # transposition
    ("https://c1tibank.com/secure/login", "MALICIOUS", "citibank.com"),
    # --- look-alike / brand-prefix / suffix ---
    ("https://example-secure.com/", "SUSPICIOUS", "example.com"),
    ("https://example-login.com/", "SUSPICIOUS", "example.com"),
    ("https://example.com.security-example.com/", "MALICIOUS", "example.com"),
    ("https://securityexample.com/", "SUSPICIOUS", "example.com"),
    # --- unicode homoglyph / punycode ---
    ("https://еxample.com/", "MALICIOUS", "example.com"),
    ("https://xn--xample-2of.com/", "MALICIOUS", "example.com"),
    # --- TLD manipulation ---
    ("https://example.co/", "MALICIOUS", "example.com"),
    ("https://citibank.xyz/", "MALICIOUS", "citibank.com"),
    # --- credential-in-URL deception ---
    ("https://example.com@malicious-attacker.com/", "SUSPICIOUS", None),
    # --- known threat intel ---
    ("https://paypa1-secure.com/", "MALICIOUS", None),
    # --- truly unknown brand (should be UNKNOWN) ---
    ("https://randombrandxyz.com/", "UNKNOWN", None),
]


@pytest.fixture(scope="module")
def analyzer(client):
    return UrlAnalyzer(org_id=1)


@pytest.mark.parametrize("url,expected,matched", DATASET,
                         ids=[d[0] for d in DATASET])
def test_analyzer_classifications(analyzer, url, expected, matched):
    result = analyzer.analyze(url, source="TEST")
    assert result.classification == expected, f"{url}: got {result.classification} " \
        f"score={result.risk_score} reasons={result.reasons}"
    if matched:
        assert result.matched_domain == matched, f"{url} matched {result.matched_domain}"


def test_analyzer_produces_reasons(analyzer):
    r = analyzer.analyze("https://examp1e.com/", source="TEST")
    assert len(r.reasons) >= 1
    assert isinstance(r.risk_score, int)
    assert 0 <= r.risk_score <= 100


def test_analyzer_trusted_green(client):
    r = UrlAnalyzer(org_id=1).analyze(
        "https://maybank2u.com/login", source="TEST"
    )
    assert r.classification == "SAFE"
    assert r.trusted is True
    assert r.risk_score == 0


def test_warning_page_payload_shape(analyzer, client):
    r = analyzer.analyze("https://example-login-security.com/", source="TEST")
    d = r.to_dict()
    for key in ("url", "registered_domain", "risk_score", "classification",
                "reasons", "safe_to_visit"):
        assert key in d