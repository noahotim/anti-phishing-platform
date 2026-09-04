"""URL analysis endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import database
from ..audit import audit
from ..content_policy import CATEGORY_LABELS
from ..security import CurrentUser, client_ip, get_current_user, get_optional_user
from ..services.analyzer import UrlAnalyzer

router = APIRouter(prefix="/api/analyze", tags=["analyze"])


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096, json_schema_extra={
        "example": "https://examp1e.com/login"})


@router.post("/url")
def analyze(
    req: AnalyzeRequest,
    request: Request,
    user: Optional[CurrentUser] = Depends(get_optional_user),
):
    if not (req.url or "").strip():
        raise HTTPException(status_code=422, detail="url is required")
    org_id = user.org_id if user else 1
    result = UrlAnalyzer(
        org_id=org_id, user_id=user.id if user else None
    ).analyze(req.url.strip(), source="EMPLOYEE")
    audit(action="SCAN_URL", actor_id=user.id if user else None,
          actor_email=user.email if user else "anonymous",
          org_id=org_id, ip=client_ip(request),
          new={"url": req.url[:200], "classification": result.classification,
               "risk_score": result.risk_score})
    return result.to_dict()


@router.post("/precheck")
def precheck(req: AnalyzeRequest, request: Request):
    """Anonymous, side-effect-free verdict for browser-guard integrations.

    Runs the full detection pipeline but writes no scan row and no audit
    entry, so a browser extension can check every navigation cheaply.
    """
    if not (req.url or "").strip():
        raise HTTPException(status_code=422, detail="url is required")
    result = UrlAnalyzer(org_id=1, persist=False).analyze(
        req.url.strip(), source="PRECHECK"
    )
    d = result.to_dict()
    blocked = d.get("classification") == "MALICIOUS"
    category = d.get("blocked_category") or ""
    label = CATEGORY_LABELS.get(category, category) if category else ""
    reasons = d.get("reasons") or []
    reason = ""
    if category:
        for r in reversed(reasons):
            if "policy" in r.lower():
                reason = r
                break
    if not reason and reasons:
        reason = reasons[0]
    return {
        "blocked": blocked,
        "content_blocked": bool(d.get("content_blocked")),
        "blocked_category": category or None,
        "blocked_label": label or None,
        "blocked_reason": reason or None,
        "classification": d.get("classification"),
        "risk_score": d.get("risk_score"),
        "matched_domain": d.get("matched_domain"),
        "safe_to_visit": bool(d.get("safe_to_visit")),
    }


@router.get("/{scan_id}")
def get_scan(scan_id: int, user: CurrentUser = Depends(get_current_user)):
    row = database.fetchone(
        "SELECT * FROM url_scans WHERE id=? AND org_id=?", (scan_id, user.org_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    ti = database.fetchall(
        "SELECT * FROM threat_intel_results WHERE url_scan_id=?", (scan_id,)
    )
    import json
    out = dict(row)
    for col in ("signals", "reasons", "details"):
        try:
            out[col] = json.loads(out.get(col) or ([] if col != "details" else "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    signals = out.get("signals") if isinstance(out.get("signals"), dict) else {}
    out["content_blocked"] = bool(signals.get("content_blocked"))
    out["blocked_category"] = signals.get("blocked_category")
    out["threat_intel"] = [dict(t) for t in ti]
    return out