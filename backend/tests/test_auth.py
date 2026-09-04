"""Authentication and role-based access control tests."""
from __future__ import annotations


def test_login_success(client):
    r = client.post("/api/auth/login", json={
        "email": "super@company-example.com",
        "password": "CorrectHorseBatteryStaple!1",
    })
    assert r.status_code == 200
    assert "token" in r.json()
    assert r.json()["user"]["role"] == "SUPER_ADMIN"


def test_login_bad_password(client):
    r = client.post("/api/auth/login", json={
        "email": "super@company-example.com",
        "password": "wrong-password",
    })
    assert r.status_code == 401


def test_login_validation(client):
    r = client.post("/api/auth/login", json={"email": "x", "password": "y"})
    assert r.status_code == 422


def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_with_token(client, super_headers):
    r = client.get("/api/auth/me", headers=super_headers)
    assert r.status_code == 200
    assert r.json()["email"] == "super@company-example.com"


def test_logout_revokes_token(client):
    token = client.post("/api/auth/login", json={
        "email": "super@company-example.com",
        "password": "CorrectHorseBatteryStaple!1",
    }).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/auth/logout", headers=headers)
    assert r.status_code == 200
    r2 = client.get("/api/auth/me", headers=headers)
    assert r2.status_code == 401


# ---- RBAC --------------------------------------------------------------
def test_employee_cannot_manage_domains(client, employee_headers):
    r = client.get("/api/trusted-domains", headers=employee_headers)
    assert r.status_code == 403


def test_employee_cannot_view_dashboard(client, employee_headers):
    r = client.get("/api/dashboard/statistics", headers=employee_headers)
    assert r.status_code == 403


def test_analyst_can_view_dashboard_not_manage_domains(client, analyst_headers):
    assert client.get("/api/dashboard/statistics", headers=analyst_headers).status_code == 200
    assert client.get("/api/trusted-domains", headers=analyst_headers).status_code == 403


def test_admin_can_manage_domains(client, admin_headers):
    assert client.get("/api/trusted-domains", headers=admin_headers).status_code == 200


def test_only_super_admin_creates_users(client, admin_headers):
    r = client.post("/api/users", json={
        "email": "nope@example.com", "role": "EMPLOYEE",
        "password": "Password123!",
    }, headers=admin_headers)
    assert r.status_code == 403


def test_employee_can_scan_and_report(client, employee_headers):
    assert client.post("/api/analyze/url",
                       json={"url": "https://examp1e.com/"},
                       headers=employee_headers).status_code == 200
    r = client.post("/api/reports", json={
        "url": "https://examp1e.com/", "comment": "looks odd",
    }, headers=employee_headers)
    assert r.status_code == 201
    assert r.json()["status"] == "NEW"


def test_employee_cannot_review_reports(client, employee_headers):
    r = client.put("/api/reports/1", json={"status": "RESOLVED"},
                   headers=employee_headers)
    assert r.status_code == 403


def test_invalid_token_rejected(client):
    r = client.get("/api/auth/me",
                   headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401