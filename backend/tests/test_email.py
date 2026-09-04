"""Email phishing analysis tests."""
from __future__ import annotations

from app.services.email_analyzer import EmailAnalyzer
from app.services.risk_scorer import MALICIOUS, SUSPICIOUS

TRUSTED = ["company.com", "google.com", "company-example.com"]


def _analyzer(client):
    return EmailAnalyzer(
        org_id=1,
        trusted_domains=TRUSTED,
    )


def test_sender_impersonation_by_substitution(client):
    r = _analyzer(client).analyze_email(
        from_header="accounts@cornpany.com",
        subject="Password reset",
        body="Please verify now",
    )
    assert r.impersonates == "company.com"
    assert r.classification in (SUSPICIOUS, MALICIOUS)


def test_safe_email_is_safe(client):
    r = _analyzer(client).analyze_email(
        from_header="it@company-example.com",
        subject="Lunch menu",
        body="Chicken rice on Thursday.",
        links=[],
    )
    assert r.classification == "SAFE"


def test_link_text_mismatch_and_link_analysis(client):
    r = _analyzer(client).analyze_email(
        from_header="it@company-example.com",
        subject="Check this",
        body="",
        links=[
            {"text": "company-example.com",
             "href": "https://examp1e.com/login"},
        ],
    )
    assert r.link_findings
    assert any(l.hostname and l.hostname != l.display_text
               for l in r.display_mismatches)
    assert r.risk_score > 0


def test_keywords_and_attachment_risks(client):
    r = _analyzer(client).analyze_email(
        from_header="random@not-an-approved-domain.net",
        subject="URGENT: invoice payment required",
        body="",
        attachments=[{"filename": "invoice.exe", "mime_type": "application/x-msdownload"}],
    )
    assert "urgent" in r.keyword_hits or "invoice" in r.keyword_hits
    assert r.attachment_risks == ["invoice.exe"]
    assert r.risk_score >= 20
    assert r.classification in (SUSPICIOUS, MALICIOUS)


def test_reply_to_impersonation(client):
    r = _analyzer(client).analyze_email(
        from_header="support@thirdparty.io",
        reply_to="hr@company-examle.com",  # 'ple' -> 'pel' transposition
        subject="Onboarding",
        body="",
    )
    assert r.reply_to_domain == "company-examle.com"
    assert r.risk_score > 0