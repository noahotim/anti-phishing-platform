"""Pytest fixtures: isolated temp database, seeded app, http client."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# --- configure environment BEFORE importing the app ---------------------
_tmp = Path(tempfile.mkdtemp(prefix="aph_tests_"))
os.environ["DATABASE_PATH"] = str(_tmp / "test.db")
os.environ["SEED_ON_STARTUP"] = "true"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["APP_DEBUG"] = "false"
os.environ["TI_SYNC_ENABLED"] = "false"
os.environ["DEFAULT_ADMIN_EMAIL"] = "super@company-example.com"
os.environ["DEFAULT_ADMIN_PASSWORD"] = "CorrectHorseBatteryStaple!1"

_BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND))

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def super_token(client):
    r = client.post(
        "/api/auth/login",
        json={"email": "super@company-example.com",
              "password": "CorrectHorseBatteryStaple!1"},
    )
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture(scope="session")
def super_headers(super_token):
    return {"Authorization": f"Bearer {super_token}"}


@pytest.fixture(scope="session")
def admin_headers(client, super_headers):
    r = client.post(
        "/api/users",
        json={
            "email": "admin@company-example.com",
            "full_name": "Admin",
            "role": "ADMIN",
            "password": "AdminPassw0rd!",
            "status": "ACTIVE",
        },
        headers=super_headers,
    )
    assert r.status_code == 201, r.text
    token = client.post(
        "/api/auth/login",
        json={"email": "admin@company-example.com", "password": "AdminPassw0rd!"},
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def analyst_headers(client, super_headers):
    r = client.post(
        "/api/users",
        json={
            "email": "analyst@company-example.com",
            "full_name": "Analyst",
            "role": "SECURITY_ANALYST",
            "password": "AnalystPassw0rd!",
            "status": "ACTIVE",
        },
        headers=super_headers,
    )
    assert r.status_code == 201, r.text
    token = client.post(
        "/api/auth/login",
        json={"email": "analyst@company-example.com", "password": "AnalystPassw0rd!"},
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def employee_headers(client, super_headers):
    r = client.post(
        "/api/users",
        json={
            "email": "employee@company-example.com",
            "full_name": "Employee",
            "role": "EMPLOYEE",
            "password": "EmployeePassw0rd!",
            "status": "ACTIVE",
        },
        headers=super_headers,
    )
    assert r.status_code == 201, r.text
    token = client.post(
        "/api/auth/login",
        json={"email": "employee@company-example.com", "password": "EmployeePassw0rd!"},
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}