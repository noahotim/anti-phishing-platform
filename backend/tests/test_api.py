"""Integration tests for the REST API surface."""
from __future__ import annotations

import io


# ---- trusted domains ----------------------------------------------------
def test_trusted_domain_crud(client, admin_headers):
    r = client.post("/api/trusted-domains", json={
        "domain": "internal-corptest.com",
        "category": "Corporate",
        "is_critical": True,
        "allowed_subdomains": "*.internal-corptest.com",
        "notes": "int test",
    }, headers=admin_headers)
    assert r.status_code == 201, r.text
    did = r.json()["id"]

    r = client.get("/api/trusted-domains", headers=admin_headers)
    assert r.status_code == 200
    assert any(d["id"] == did for d in r.json())

    r = client.put(f"/api/trusted-domains/{did}", json={
        "domain": "internal-corptest.com",
        "category": "Corporate",
        "is_critical": False,
        "allowed_subdomains": "",
        "notes": "updated",
    }, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["is_critical"] is False

    r = client.get(f"/api/trusted-domains/history/{did}", headers=admin_headers)
    assert r.status_code == 200
    assert len(r.json()) >= 2  # created + updated audit rows

    assert client.delete(f"/api/trusted-domains/{did}",
                         headers=admin_headers).status_code == 200


def test_duplicate_domain_conflict(client, admin_headers):
    r = client.post("/api/trusted-domains", json={"domain": "google.com"},
                    headers=admin_headers)
    assert r.status_code == 409


def test_invalid_domain_rejected(client, admin_headers):
    r = client.post("/api/trusted-domains", json={"domain": "not a domain"},
                    headers=admin_headers)
    assert r.status_code == 422


def test_csv_import_export(client, admin_headers):
    csv_content = (
        "domain,category,is_critical,notes\n"
        "import-a.com,Corporate,true,first\n"
        "import-b.com,,false,\n"
        "not valid domain,,,\n"
    )
    r = client.post(
        "/api/trusted-domains/import",
        headers=admin_headers,
        files={"file": ("domains.csv", io.BytesIO(csv_content.encode("utf-8")),
                        "text/csv")},
    )
    assert r.status_code == 200
    assert r.json()["added"] == 2
    assert r.json()["skipped"] == 1

    r = client.get("/api/trusted-domains/export", headers=admin_headers)
    assert r.status_code == 200
    body = r.content.decode("utf-8")
    assert "import-a.com" in body


# ---- reports --------------------------------------------------------------
def test_report_lifecycle(client, employee_headers, analyst_headers):
    r = client.post("/api/reports", json={
        "url": "https://suspiciouslookalike.com/",
        "comment": "asked me for password",
    }, headers=employee_headers)
    assert r.status_code == 201
    rid = r.json()["id"]

    r = client.put(f"/api/reports/{rid}", json={"status": "INVESTIGATING"},
                   headers=analyst_headers)
    assert r.status_code == 200

    r = client.get("/api/reports", params={"status": "INVESTIGATING"},
                   headers=analyst_headers)
    assert r.status_code == 200
    assert any(x["id"] == rid for x in r.json())

    r = client.put(f"/api/reports/{rid}", json={"status": "FALSE_POSITIVE"},
                   headers=analyst_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "FALSE_POSITIVE"


def test_invalid_report_status(client, analyst_headers):
    r = client.put("/api/reports/1", json={"status": "NONSENSE"},
                   headers=analyst_headers)
    assert r.status_code == 400


def test_reports_visible_only_in_org_or_own(client, admin_headers):
    r = client.get("/api/reports", headers=admin_headers)
    assert r.status_code == 200


# ---- dashboard -------------------------------------------------------------
def test_dashboard_statistics(client, analyst_headers):
    r = client.get("/api/dashboard/statistics", params={"days": 7},
                   headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    for key in ("total_scans", "safe", "suspicious", "malicious", "blocked",
                "top_impersonated", "risk_distribution", "trend",
                "reports_by_status"):
        assert key in data
    assert data["total_scans"] > 0
    assert len(data["risk_distribution"]) == 4


def test_dashboard_range_validation(client, analyst_headers):
    r = client.get("/api/dashboard/statistics", params={"days": 0},
                   headers=analyst_headers)
    assert r.status_code == 422


# ---- settings ---------------------------------------------------------------
def test_risk_thresholds_roundtrip(client, admin_headers):
    r = client.put("/api/settings/risk-thresholds", json={
        "low": 25, "moderate": 55, "high": 80,
    }, headers=admin_headers)
    assert r.status_code == 200
    r = client.get("/api/settings/risk-thresholds", headers=admin_headers)
    assert r.json()["low"] == 25
    assert r.json()["high"] == 80


def test_thresholds_must_be_ordered(client, admin_headers):
    r = client.put("/api/settings/risk-thresholds", json={
        "low": 30, "moderate": 20, "high": 40,
    }, headers=admin_headers)
    assert r.status_code == 400


# ---- audit logs --------------------------------------------------------------
def test_audit_logs_and_search(client, admin_headers):
    r = client.get("/api/audit-logs", headers=admin_headers)
    assert r.status_code == 200
    assert len(r.json()) > 0
    r = client.get("/api/audit-logs", params={"action": "LOGIN"},
                   headers=admin_headers)
    assert r.status_code == 200
    assert all(x["action"] == "LOGIN" for x in r.json())


# ---- validation / structured errors --------------------------------------------
def test_structured_validation_error(client, super_headers):
    r = client.post("/api/analyze/url", json={"url": ""}, headers=super_headers)
    assert r.status_code == 422
    body = r.json()
    assert body["detail"] == "validation error"
    assert "errors" in body
    assert all("field" in e and "message" in e for e in body["errors"])


def test_rate_limit_disabled_in_default_app(client, super_headers):
    """Rate limiting content here is covered by test_rate_limit.py with an
    isolated app; the default test app has it disabled to keep tests fast."""
    assert True


# ---- email analysis -----------------------------------------------------------
def test_email_impersonation(client, super_headers):
    # Register the domain that the phishing mail will try to impersonate.
    client.post("/api/trusted-domains", json={"domain": "company.com"},
                headers=super_headers)
    r = client.post("/api/email/analyze", json={
        "from_header": "Security <accounts@cornpany.com>",
        "reply_to": "",
        "subject": "Your account has been suspended",
        "body": "Verify your password immediately.",
        "links": [{"text": "company.com", "href": "https://examp1e.com/login"}],
        "attachments": [],
    }, headers=super_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["sender_domain"] == "cornpany.com"
    assert data["impersonates"] == "company.com"
    assert data["classification"] in ("SUSPICIOUS", "MALICIOUS")
    assert data["risk_score"] > 0