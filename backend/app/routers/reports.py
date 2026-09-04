"""Phishing reporting endpoints."""
from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import database
from ..audit import audit
from ..security import (
    CurrentUser,
    client_ip,
    get_current_user,
    require_analyst,
)
from ..services.analyzer import UrlAnalyzer

router = APIRouter(prefix="/api/reports", tags=["reports"])

VALID_STATUSES = ("NEW", "INVESTIGATING", "CONFIRMED_THREAT", "FALSE_POSITIVE", "RESOLVED")


class ReportIn(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    comment: str = Field(default="", max_length=4000)


class ReportStatusIn(BaseModel):
    status: str = Field(min_length=3, max_length=24)
    comment: str = Field(default="", max_length=4000)


@router.post("", status_code=201)
def create_report(
    body: ReportIn,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
):
    analysis = UrlAnalyzer(org_id=user.org_id, user_id=user.id).analyze(
        body.url.strip(), source="REPORT"
    )
    rep_id = database.execute(
        """
        INSERT INTO threat_reports
            (org_id, user_id, url, analysis, comment, status, created_at)
        VALUES (?,?,?,?,?, 'NEW', ?)
        """,
        (
            user.org_id, user.id, body.url.strip(),
            json.dumps(analysis.to_dict()), body.comment.strip(),
            database.utcnow_iso(),
        ),
    )
    audit(action="CREATE_REPORT", entity="threat_report", entity_id=rep_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request),
          new={"url": body.url[:200], "classification": analysis.classification})
    return {"id": rep_id, "status": "NEW", "analysis": analysis.to_dict()}


@router.get("")
def list_reports(
    status: Optional[str] = Query(default=None),
    mine: bool = Query(default=False),
    user: CurrentUser = Depends(get_current_user),
):
    if mine and user.role == "EMPLOYEE":
        rows = database.fetchall(
            "SELECT * FROM threat_reports WHERE user_id=? ORDER BY id DESC LIMIT 200",
            (user.id,),
        )
    elif user.role == "EMPLOYEE":
        rows = database.fetchall(
            "SELECT * FROM threat_reports WHERE user_id=? ORDER BY id DESC LIMIT 200",
            (user.id,),
        )
    else:
        if status:
            if status not in VALID_STATUSES:
                raise HTTPException(status_code=400, detail="invalid status")
            rows = database.fetchall(
                "SELECT * FROM threat_reports WHERE org_id=? AND status=? ORDER BY id DESC LIMIT 500",
                (user.org_id, status),
            )
        else:
            rows = database.fetchall(
                "SELECT * FROM threat_reports WHERE org_id=? ORDER BY id DESC LIMIT 500",
                (user.org_id,),
            )
    out = []
    for r in rows:
        item = dict(r)
        try:
            item["analysis"] = json.loads(r["analysis"] or "{}")
        except json.JSONDecodeError:
            item["analysis"] = {}
        out.append(item)
    return out


@router.get("/{report_id}")
def get_report(
    report_id: int,
    user: CurrentUser = Depends(get_current_user),
):
    row = database.fetchone("SELECT * FROM threat_reports WHERE id=?", (report_id,))
    if row is None or row["org_id"] != user.org_id:
        if not (row and (user.role != "EMPLOYEE" or row["user_id"] == user.id)):
            raise HTTPException(status_code=404, detail="report not found")
    item = dict(row)
    try:
        item["analysis"] = json.loads(row["analysis"] or "{}")
    except json.JSONDecodeError:
        item["analysis"] = {}
    return item


@router.put("/{report_id}")
def update_report_status(
    report_id: int,
    body: ReportStatusIn,
    request: Request,
    user: CurrentUser = Depends(require_analyst),
):
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {VALID_STATUSES}")
    row = database.fetchone(
        "SELECT * FROM threat_reports WHERE id=? AND org_id=?", (report_id, user.org_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="report not found")
    prev = dict(row)
    database.execute(
        """
        UPDATE threat_reports SET status=?, comment=?, reviewed_by=?, reviewed_at=?
        WHERE id=?
        """,
        (body.status, body.comment.strip(), user.id, database.utcnow_iso(), report_id),
    )
    audit(action="UPDATE_REPORT_STATUS", entity="threat_report", entity_id=report_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request),
          prev={"status": prev["status"]}, new={"status": body.status})
    return {"id": report_id, "status": body.status}