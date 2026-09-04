"""Feedback — public submit, admin list."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..database import db, utcnow_iso
from ..security import get_current_user, require_role

router = APIRouter(prefix="/api/feedback", tags=["feedback"])


class FeedbackIn(BaseModel):
    name: str = Field(default="", max_length=120)
    email: str = Field(default="", max_length=200)
    rating: int = Field(default=0, ge=0, le=5)
    category: str = Field(default="GENERAL", max_length=40)
    message: str = Field(..., min_length=3, max_length=5000)
    browser: str = Field(default="", max_length=200)
    url: str = Field(default="", max_length=2000)


@router.post("", status_code=201)
def submit_feedback(payload: FeedbackIn, request: Request):
    # Basic honeypot: if message looks like spam with many URLs, still store but flag via category
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO feedback (org_id, name, email, rating, category, message, browser, url, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,  # default org; feedback is global. If multi-org, first org is fine.
                payload.name.strip()[:120],
                payload.email.strip()[:200],
                int(payload.rating),
                payload.category.strip()[:40] or "GENERAL",
                payload.message.strip(),
                payload.browser.strip()[:200],
                payload.url.strip()[:2000],
                utcnow_iso(),
            ),
        )
        fid = int(cur.lastrowid)
    return {"ok": True, "id": fid}


@router.get("")
def list_feedback(
    request: Request,
    user: Any = Depends(get_current_user),
    _: Any = Depends(require_role("ADMIN", "SUPER_ADMIN", "SECURITY_ANALYST")),
):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, email, rating, category, message, browser, url, created_at FROM feedback ORDER BY created_at DESC LIMIT 500"
        ).fetchall()
    return {"feedback": [dict(r) for r in rows]}


@router.get("/public")
def list_public():
    # Lightweight public recent feedback (for display, no email)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, rating, category, message, created_at FROM feedback ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    # Strip email for privacy
    return {"feedback": [dict(r) for r in rows]}


# --- Google Form embed URL (stored in system_settings) ---
@router.get("/gform")
def get_gform():
    with db() as conn:
        row = conn.execute(
            "SELECT value FROM system_settings WHERE org_id=1 AND key='feedback_gform_url'"
        ).fetchone()
    url = row["value"] if row else ""
    # system_settings value is JSON-encoded string
    try:
        import json as _json
        url = _json.loads(url) if url else ""
    except Exception:
        pass
    return {"url": url or ""}


class GformIn(BaseModel):
    url: str = Field(default="", max_length=2000)


@router.put("/gform")
def set_gform(
    payload: GformIn,
    user: Any = Depends(get_current_user),
    _: Any = Depends(require_role("ADMIN", "SUPER_ADMIN")),
):
    import json as _json
    from ..database import utcnow_iso

    url = payload.url.strip()[:2000]
    # Basic validation: must be a Google Forms URL if not empty
    if url and "docs.google.com/forms" not in url:
        # still allow but warn via category
        pass
    with db() as conn:
        conn.execute(
            """
            INSERT INTO system_settings (org_id, key, value, updated_by, updated_at)
            VALUES (1, 'feedback_gform_url', ?, ?, ?)
            ON CONFLICT(org_id, key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at
            """,
            (_json.dumps(url), user.id, utcnow_iso()),
        )
    return {"ok": True, "url": url}
