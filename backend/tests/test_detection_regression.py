"""Regression tests for evidence-based detection.

These tests enforce the central invariant: an unknown domain is not suspicious
by itself.  Suspicion requires impersonation, URL-attack, or confirmed-threat
evidence.
"""
from __future__ import annotations

import logging

import pytest

from app import database
from app.services.analyzer import UrlAnalyzer
from app.services.url_parser import parse_url, split_registered_domain


def make_analyzer(rows: list[dict] | None = None) -> UrlAnalyzer:
    """Use seeded trust by default; pass an explicit list to isolate brands."""
    return UrlAnalyzer(
        org_id=1,
        trusted_domains=rows,
        persist=False,
        thresholds={"low": 20, "moderate": 59, "high": 79},
    )


def untrusted_analyzer() -> UrlAnalyzer:
    """An analyzer with no trusted brands at all, for unknown-domain tests."""
    return make_analyzer([])



def brand_rows(*domains: str, critical: bool = False) -> list[dict]:
    return [
        {
            "normalized_domain": domain,
            "is_critical": critical,
            "allowed_subdomains": "",
        }
        for domain in domains
    ]


@pytest.fixture(scope="module", autouse=True)
def _seeded_test_database(client):
    """Ensure the isolated test database is seeded before direct analysis."""
    return client


def test_registrable_domain_extraction_for_institutional_suffixes():
    registered, subdomain = split_registered_domain("www.sun.ac.ug")
    assert registered == "sun.ac.ug"
    assert subdomain == "www"

    registered, subdomain = split_registered_domain("sun.ac.ug.attacker.com")
    assert registered == "attacker.com"
    assert subdomain == "sun.ac.ug"


def test_unknown_academic_domain_is_not_suspicious():
    analyzer = untrusted_analyzer()

    result = analyzer.analyze("https://sun.ac.ug/", source="TEST")
    payload = result.to_dict()

    assert result.registered_domain == "sun.ac.ug"
    assert result.classification == "UNKNOWN"
    assert result.risk_score == 5
    assert result.blocked is False
    assert payload["evidence"]["weak"] == ["not_in_trusted_database"]
    assert "institutional_academic_namespace" in payload["evidence"]["contextual"]
    assert "valid_domain_structure" in payload["evidence"]["contextual"]
    assert payload["confidence"] >= 0.85
    assert payload["explanation"]


@pytest.mark.parametrize(
    "host",
    ["novelbrandtest.com", "novelbrandtest.org", "novelbrandtest.net",
     "novelbrandtest.co.uk", "novelbrandtest.ug"],
)
def test_changed_tld_alone_is_not_suspicious(host: str):
    result = untrusted_analyzer().analyze(f"https://{host}/", source="TEST")

    assert result.classification == "UNKNOWN"
    assert result.blocked is False
    assert result.risk_score <= 20
    assert result.to_dict()["evidence"]["strong"] == []
    assert result.to_dict()["evidence"]["medium"] == []


@pytest.mark.parametrize(
    "host",
    ["sun.ac.ug", "university.ac.ug", "college.ac.ug"],
)
def test_academic_namespaces_are_contextual_not_trust(host: str):
    result = untrusted_analyzer().analyze(f"https://{host}/", source="TEST")

    assert result.classification == "UNKNOWN"
    assert "institutional_academic_namespace" in result.to_dict()["evidence"]["contextual"]


def test_institutional_attack_is_detected_and_blocked():
    result = make_analyzer().analyze(
        "https://sun.ac.ug.attacker-example.com/login", source="TEST"
    )
    payload = result.to_dict()

    assert result.registered_domain == "attacker-example.com"
    assert "deceptive_subdomain" in payload["evidence"]["strong"]
    assert "credential_path_with_suspicious_domain" in payload["evidence"]["medium"]
    assert result.classification in ("SUSPICIOUS", "HIGH_RISK", "MALICIOUS")
    assert result.risk_score >= 40
    assert result.blocked is True
    assert result.matched_domain == "sun.ac.ug"


def test_deceptive_compound_namespace_is_evaluated_as_phishing():
    result = untrusted_analyzer().analyze("https://sun-university-login.xyz/", source="TEST")
    payload = result.to_dict()

    assert result.classification == "SUSPICIOUS"
    assert "deceptive_domain_construction" in payload["evidence"]["medium"]
    assert "high_risk_namespace" in payload["evidence"]["medium"]
    assert payload["explanation"]


@pytest.mark.parametrize(
    ("url", "trusted", "expected", "strong"),
    [
        ("https://gogle.com/", "google.com", "google.com", "very_close_typosquat"),
        ("https://gooogle.com/", "google.com", "google.com", "very_close_typosquat"),
        ("https://micros0ft.com/", "microsoft.com", "microsoft.com", "confirmed_homograph"),
        ("https://paypa1.com/", "paypal.com", "paypal.com", "confirmed_homograph"),
    ],
)
def test_typosquatting_generates_impersonation_evidence(
    url: str, trusted: str, expected: str, strong: str
):
    analyzer = make_analyzer(brand_rows("google.com", "microsoft.com", "paypal.com"))
    result = analyzer.analyze(url, source="TEST")

    assert result.classification in ("SUSPICIOUS", "HIGH_RISK")
    assert strong in result.to_dict()["evidence"]["strong"]
    assert result.matched_domain == expected


def test_homograph_generates_strong_evidence():
    analyzer = make_analyzer(brand_rows("example.com"))
    result = analyzer.analyze("https://\u0435xample.com/", source="TEST")

    assert result.classification in ("SUSPICIOUS", "HIGH_RISK")
    assert "confirmed_homograph" in result.to_dict()["evidence"]["strong"]
    assert result.matched_domain == "example.com"


def test_punycode_impersonation_generates_strong_evidence():
    analyzer = make_analyzer(brand_rows("example.com"))
    result = analyzer.analyze("https://xn--xample-2of.com/", source="TEST")

    assert result.classification in ("SUSPICIOUS", "HIGH_RISK")
    assert "confirmed_homograph" in result.to_dict()["evidence"]["strong"]


@pytest.mark.parametrize(
    ("url", "registered", "trusted"),
    [
        ("https://google.com.attacker.com/", "attacker.com", "google.com"),
        ("https://paypal.com.attacker.net/", "attacker.net", "paypal.com"),
        (
            "https://microsoft.com.verify.example.com/",
            "example.com",
            "microsoft.com",
        ),
    ],
)
def test_deceptive_subdomains_use_registrable_domain(url: str, registered: str, trusted: str):
    analyzer = make_analyzer(brand_rows("google.com", "paypal.com", "microsoft.com"))
    result = analyzer.analyze(url, source="TEST")

    assert result.registered_domain == registered
    assert "deceptive_subdomain" in result.to_dict()["evidence"]["strong"]
    assert result.matched_domain == trusted
    assert result.classification in ("SUSPICIOUS", "HIGH_RISK", "MALICIOUS")


def test_userinfo_attack_uses_authoritative_host():
    result = make_analyzer(brand_rows("google.com")).analyze(
        "https://google.com@attacker.com/login", source="TEST"
    )
    payload = result.to_dict()

    assert result.registered_domain == "attacker.com"
    assert "credential_userinfo" in payload["evidence"]["strong"]
    assert "credential_path_with_suspicious_domain" in payload["evidence"]["medium"]
    assert result.classification == "HIGH_RISK"
    assert result.blocked is True


def test_ip_login_is_contextual_but_not_automatically_malicious():
    result = untrusted_analyzer().analyze("http://192.168.1.10/login", source="TEST")
    payload = result.to_dict()

    assert result.classification == "UNKNOWN"
    assert result.blocked is False
    assert "ip_host_with_credential" in payload["evidence"]["medium"]
    assert "private_network_host" in payload["evidence"]["contextual"]


def test_confirmed_threat_intel_has_priority():
    result = make_analyzer().analyze("https://paypa1-secure.com/", source="TEST")
    payload = result.to_dict()

    assert result.classification == "MALICIOUS"
    assert result.risk_score >= 90
    assert result.blocked is True
    assert payload["evidence"]["critical"] == ["known_malicious"]


def test_trusted_domain_is_safe_but_not_required_for_unknown():
    trusted = make_analyzer().analyze("https://www.google.com/", source="TEST")
    unknown = make_analyzer().analyze("https://sun.ac.ug/", source="TEST")

    assert trusted.classification == "SAFE"
    assert trusted.blocked is False
    assert unknown.classification == "UNKNOWN"
    assert unknown.blocked is False


def test_explainable_api_shape(client):
    response = client.post("/api/analyze/url", json={"url": "https://novelbrandtest.ug/"})
    assert response.status_code == 200
    payload = response.json()

    assert payload["classification"] == "UNKNOWN"
    assert payload["blocked"] is False
    assert set(payload["evidence"]) == {"critical", "strong", "medium", "weak", "contextual"}
    assert isinstance(payload["confidence"], float)
    assert payload["explanation"]
    assert payload["password"] == ""
    assert payload["details"]["registered_domain"] == "novelbrandtest.ug"


def test_precheck_supports_high_risk_and_leaves_unknown_accessible(client):
    unknown = client.post("/api/analyze/precheck", json={"url": "https://sun.ac.ug/"})
    assert unknown.status_code == 200
    assert unknown.json()["classification"] == "UNKNOWN"
    assert unknown.json()["blocked"] is False

    attack = client.post(
        "/api/analyze/precheck",
        json={"url": "https://sun.ac.ug.attacker-example.com/login"},
    )
    assert attack.status_code == 200
    assert attack.json()["blocked"] is True
    assert attack.json()["classification"] in ("SUSPICIOUS", "HIGH_RISK", "MALICIOUS")


def test_suspicious_verdict_logs_structured_redacted_evidence(caplog):
    analyzer = make_analyzer(brand_rows("example.com"))
    with caplog.at_level(logging.WARNING, logger="analyzer"):
        analyzer.analyze(
            "https://example-secure.com/login?next=https://example.com/",
            source="TEST",
        )

    records = [record for record in caplog.records if "suspicious_url" in record.message]
    assert records
    message = records[0].getMessage()
    assert "classification=HIGH_RISK" in message
    for token in (
        "registrable_domain=example-secure.com",
        "strong=",
        "medium=",
        "weak=",
        "threat_intel=",
        "matched=example.com",
    ):
        assert token in message


def test_credentials_are_redacted_from_persisted_verdicts():
    analyzer = UrlAnalyzer(org_id=1, persist=True)
    result = analyzer.analyze("https://scanuser:Sup3rSecret123@example.com/", source="TEST")
    assert result.classification == "SAFE"
    assert result.to_dict()["password"] == ""

    row = database.fetchone(
        "SELECT url, signals, reasons, details FROM url_scans "
        "WHERE org_id=1 AND hostname='example.com' ORDER BY id DESC LIMIT 1"
    )
    assert row is not None
    assert "Sup3rSecret123" not in row["url"]
    assert "Sup3rSecret123" not in row["signals"]
    assert "Sup3rSecret123" not in row["reasons"]
    assert "Sup3rSecret123" not in row["details"]
    assert "redacted-userinfo@example.com" in row["url"]


def test_trusted_suffix_cannot_be_borrowed_by_an_attacker_domain():
    analyzer = make_analyzer(brand_rows("trusted.ac.ug"))
    result = analyzer.analyze("https://trusted.ac.ug.attacker.com/", source="TEST")

    assert result.trusted is False
    assert result.registered_domain == "attacker.com"
    assert result.classification in ("UNKNOWN", "SUSPICIOUS", "HIGH_RISK", "MALICIOUS")


def test_detection_code_has_no_target_specific_bypass():
    root = __import__("pathlib").Path(__file__).resolve().parent.parent
    for name in ("app/services/analyzer.py", "app/services/detection.py"):
        text = (root / name).read_text(encoding="utf-8")
        assert 'endswith(".ac.ug")' not in text
