"""Audit log access.  Searchable by admins."""
from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, Query

from .. import database
from ..security import CurrentUser, require_admin

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("")
def list_audit_logs(
    user: CurrentUser = Depends(require_admin),
    action: Optional[str] = Query(default=None),
    actor: Optional[str] = Query(default=None),
    entity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    where = ["org_id=?"]
    params: list = [user.org_id]
    if action:
        where.append("action=?")
        params.append(action)
    if actor:
        where.append("lower(actor_email) LIKE lower(?)")
        params.append(f"%{actor}%")
    if entity:
        where.append("entity=?")
        params.append(entity)
    rows = database.fetchall(
        f"""
        SELECT * FROM audit_logs WHERE {" AND ".join(where)}
        ORDER BY id DESC LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    )
    out = []
    for r in rows:
        item = dict(r)
        try:
            item["prev"] = json.loads(r["prev"] or "{}")
            item["new"] = json.loads(r["new"] or "{}")
        except json.JSONDecodeError:
            item["prev"], item["new"] = {}, {}
        out.append(item)
    return out


@router.get("/actions")
def audit_actions(user: CurrentUser = Depends(require_admin)):
    rows = database.fetchall(
        "SELECT DISTINCT action FROM audit_logs WHERE org_id=? ORDER BY action",
        (user.org_id,),
    )
    return [r["action"] for r in rows]