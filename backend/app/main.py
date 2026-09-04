"""FastAPI application entrypoint.

Assembles routers, middleware (security headers, rate limiting, CORS), static
frontend hosting, startup database bootstrap and structured error responses.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .config import settings as app_settings
from .database import init_db
from .rate_limiter import RateLimitMiddleware
from .routers import (
    analyze,
    audit,
    auth,
    blocked_sites,
    dashboard,
    email,
    feedback,
    guard,
    reports,
    settings as settings_router,
    threat_intel,
    trusted_domains,
    users,
)
from .seed import seed
from .services.ti_sync import sync_live_feed_once

logging.basicConfig(
    level=logging.DEBUG if app_settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")


async def _ti_sync_loop() -> None:
    """Periodically pull fresh malicious hosts from the public URLhaus feed."""
    minutes = max(1, app_settings.ti_sync_interval_min)
    while True:
        try:
            result = await asyncio.to_thread(sync_live_feed_once)
            log.info("live threat feed: %s", result.get("last_sync"))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("live threat feed sync failed")
        try:
            await asyncio.sleep(minutes * 60)
        except asyncio.CancelledError:
            raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if app_settings.seed_on_startup:
        try:
            seed()
        except Exception:
            log.exception("seeding failed; continuing with existing data")
    sync_task = None
    if app_settings.ti_sync_enabled:
        sync_task = asyncio.create_task(_ti_sync_loop())
        log.info("live threat-intel feed enabled (every %s min)",
                 app_settings.ti_sync_interval_min)
    yield
    if sync_task is not None:
        sync_task.cancel()
        try:
            await sync_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title=app_settings.app_name,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if app_settings.debug else None,
    openapi_url="/api/openapi.json" if app_settings.debug else None,
)

# --- security headers (defense in depth) ------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src 'self' https://docs.google.com https://*.google.com https://*.gstatic.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


app.add_middleware(RateLimitMiddleware, enabled=app_settings.rate_limit_enabled)

# --- structured errors ------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "detail": "validation error",
            "errors": [
                {
                    "field": ".".join(str(x) for x in e.get("loc", [])),
                    "message": e.get("msg", ""),
                }
                for e in exc.errors()
            ],
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    headers = dict(exc.headers or {})
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers,
    )


# --- routers -----------------------------------------------------------------
app.include_router(auth.router)
app.include_router(analyze.router)
app.include_router(trusted_domains.router)
app.include_router(reports.router)
app.include_router(dashboard.router)
app.include_router(audit.router)
app.include_router(settings_router.router)
app.include_router(users.router)
app.include_router(email.router)
app.include_router(threat_intel.router)
app.include_router(blocked_sites.router)
app.include_router(guard.router)
app.include_router(feedback.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": app_settings.app_name}


# --- static frontend ---------------------------------------------------------
_root = app_settings.static_dir
_frontend_dir = _root if (_root / "index.html").exists() else None

if _frontend_dir is not None:
    app.mount(
        "/assets",
        StaticFiles(directory=str(_frontend_dir / "css")),
        name="css",
    )
    app.mount(
        "/scripts",
        StaticFiles(directory=str(_frontend_dir / "js")),
        name="js",
    )

    @app.get("/")
    async def index():
        return RedirectResponse("/app/index.html")

    app.mount(
        "/app", StaticFiles(directory=str(_frontend_dir)), name="app"
    )
    app.mount("/login", StaticFiles(directory=str(_frontend_dir)), name="login")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return JSONResponse(status_code=204, content=None)


def main():  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        reload=app_settings.debug,
    )


if __name__ == "__main__":  # pragma: no cover
    init_db()
    main()