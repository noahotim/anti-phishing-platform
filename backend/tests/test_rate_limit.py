"""Rate-limit middleware tests using an isolated app instance."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.rate_limiter import RateLimiter, RateLimitMiddleware


def _make_app(limits=None):
    inner = FastAPI()

    @inner.get("/api/ping")
    def ping(request: Request):
        return {"ok": True}

    @inner.get("/api/auth/login")
    def login(request: Request):
        return {"ok": True}

    inner.add_middleware(
        RateLimitMiddleware,
        enabled=True,
        limits=limits or {"default": "20/60second", "auth": "2/60second"},
        limiter=RateLimiter(),
    )
    return inner


def test_rate_limit_enforced():
    app = _make_app({"default": "3/60second"})
    c = TestClient(app)
    # capacity 3 => allow 3, block the 4th
    for _ in range(3):
        assert c.get("/api/ping").status_code == 200
    assert c.get("/api/ping").status_code == 429
    assert "rate limit" in c.get("/api/ping").json()["detail"]


def test_rate_limit_respects_route_groups():
    app = _make_app()
    c = TestClient(app)
    # 'auth' bucket has capacity 2 and blocks the 3rd request...
    for _ in range(2):
        assert c.get("/api/auth/login").status_code == 200
    assert c.get("/api/auth/login").status_code == 429
    # ...while the default bucket is untouched.
    assert c.get("/api/ping").status_code == 200