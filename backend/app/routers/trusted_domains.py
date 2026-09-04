"""Trusted domain management (admins) and the employee-facing approval lookup."""
from __future__ import annotations

import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form
from pydantic import BaseModel, Field

from .. import database
from ..audit import audit
from ..security import CurrentUser, client_ip, require_admin
from ..services import normalization

router = APIRouter(prefix="/api/trusted-domains", tags=["trusted-domains"])


class TrustedDomainIn(BaseModel):
    domain: str = Field(min_length=2, max_length=253)
    category: str = Field(default="Corporate", max_length=64)
    is_critical: bool = False
    allowed_subdomains: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=2000)


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "org_id": row["org_id"],
        "domain": row["domain"],
        "normalized_domain": row["normalized_domain"],
        "category": row["category"],
        "is_critical": bool(row["is_critical"]),
        "allowed_subdomains": row["allowed_subdomains"],
        "notes": row["notes"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


@router.get("")
def list_domains(
    user: CurrentUser = Depends(require_admin),
    category: Optional[str] = Query(default=None),
):
    if category:
        rows = database.fetchall(
            "SELECT * FROM trusted_domains WHERE org_id=? AND category=? ORDER BY domain",
            (user.org_id, category),
        )
    else:
        rows = database.fetchall(
            "SELECT * FROM trusted_domains WHERE org_id=? ORDER BY domain",
            (user.org_id,),
        )
    return [_row_to_dict(r) for r in rows]


@router.post("", status_code=201)
def create_domain(
    body: TrustedDomainIn,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    norm = normalization.to_ascii(body.domain)
    if not norm or "." not in norm:
        raise HTTPException(status_code=422, detail="invalid domain")
    exists = database.fetchone(
        "SELECT id FROM trusted_domains WHERE org_id=? AND normalized_domain=?",
        (user.org_id, norm),
    )
    if exists:
        raise HTTPException(status_code=409, detail="domain already trusted")
    new_id = database.execute(
        """
        INSERT INTO trusted_domains
            (org_id, domain, normalized_domain, category, is_critical,
             allowed_subdomains, notes, added_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            user.org_id, body.domain.strip(), norm, body.category,
            1 if body.is_critical else 0, body.allowed_subdomains.strip(),
            body.notes.strip(), user.id, database.utcnow_iso(),
            database.utcnow_iso(),
        ),
    )
    audit(action="CREATE_TRUSTED_DOMAIN", entity="trusted_domain", entity_id=new_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), new=body.model_dump())
    return _row_to_dict(
        database.fetchone("SELECT * FROM trusted_domains WHERE id=?", (new_id,))
    )


@router.put("/{domain_id}")
def update_domain(
    domain_id: int,
    body: TrustedDomainIn,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    row = database.fetchone(
        "SELECT * FROM trusted_domains WHERE id=? AND org_id=?",
        (domain_id, user.org_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="domain not found")
    norm = normalization.to_ascii(body.domain)
    prev = _row_to_dict(row)
    database.execute(
        """
        UPDATE trusted_domains SET domain=?, normalized_domain=?, category=?,
            is_critical=?, allowed_subdomains=?, notes=?, updated_at=?
        WHERE id=?
        """,
        (
            body.domain.strip(), norm, body.category, 1 if body.is_critical else 0,
            body.allowed_subdomains.strip(), body.notes.strip(),
            database.utcnow_iso(), domain_id,
        ),
    )
    audit(action="UPDATE_TRUSTED_DOMAIN", entity="trusted_domain", entity_id=domain_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev=prev, new=body.model_dump())
    return _row_to_dict(
        database.fetchone("SELECT * FROM trusted_domains WHERE id=?", (domain_id,))
    )


@router.delete("/{domain_id}")
def delete_domain(
    domain_id: int,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    row = database.fetchone(
        "SELECT * FROM trusted_domains WHERE id=? AND org_id=?",
        (domain_id, user.org_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="domain not found")
    database.execute("DELETE FROM trusted_domains WHERE id=?", (domain_id,))
    audit(action="DELETE_TRUSTED_DOMAIN", entity="trusted_domain", entity_id=domain_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev=_row_to_dict(row))
    return {"detail": "deleted"}


@router.post("/import")
async def import_domains(
    request: Request,
    user: CurrentUser = Depends(require_admin),
    file: UploadFile = File(...),
):
    if not file.filename:
        raise HTTPException(status_code=422, detail="file required")
    content = io.StringIO((await file.read()).decode("utf-8-sig", errors="ignore"))
    reader = csv.DictReader(content)
    expected = {"domain", "category", "is_critical", "allowed_subdomains", "notes"}
    if not reader.fieldnames or not (expected & set(reader.fieldnames)):
        raise HTTPException(
            status_code=422,
            detail="CSV must contain at least a 'domain' column",
        )
    added, skipped = 0, 0
    records = []
    for row in reader:
        domain = (row.get("domain") or "").strip()
        if not domain:
            continue
        norm = normalization.to_ascii(domain)
        if not norm or "." not in norm:
            skipped += 1
            continue
        exists = database.fetchone(
            "SELECT id FROM trusted_domains WHERE org_id=? AND normalized_domain=?",
            (user.org_id, norm),
        )
        if exists:
            skipped += 1
            continue
        records.append(
            (
                user.org_id, domain, norm,
                (row.get("category") or "Corporate").strip()[:64],
                1 if (row.get("is_critical") or "").lower() in {"1","true","yes","y"} else 0,
                (row.get("allowed_subdomains") or "").strip()[:1024],
                (row.get("notes") or "").strip()[:2000],
                user.id, database.utcnow_iso(), database.utcnow_iso(),
            )
        )
        added += 1
    database.execute_many(
        """
        INSERT INTO trusted_domains
            (org_id, domain, normalized_domain, category, is_critical,
             allowed_subdomains, notes, added_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        records,
    )
    audit(action="IMPORT_TRUSTED_DOMAINS", entity="trusted_domain",
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), new={"added": added, "skipped": skipped})
    return {"added": added, "skipped": skipped}


@router.get("/export")
def export_domains(user: CurrentUser = Depends(require_admin)):
    rows = database.fetchall(
        "SELECT * FROM trusted_domains WHERE org_id=? ORDER BY domain", (user.org_id,)
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["domain", "category", "is_critical", "allowed_subdomains", "notes"])
    for r in rows:
        writer.writerow([
            r["domain"], r["category"], r["is_critical"],
            r["allowed_subdomains"], r["notes"],
        ])
    from fastapi.responses import Response
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=trusted_domains.csv"},
    )


@router.get("/history/{domain_id}")
def domain_history(
    domain_id: int,
    user: CurrentUser = Depends(require_admin),
):
    rows = database.fetchall(
        """
        SELECT * FROM audit_logs
        WHERE org_id=? AND entity='trusted_domain' AND entity_id=?
        ORDER BY id DESC LIMIT 100
        """,
        (user.org_id, str(domain_id)),
    )
    return [
        {
            "id": r["id"], "action": r["action"], "actor_email": r["actor_email"],
            "prev": json.loads(r["prev"] or "{}"),
            "new": json.loads(r["new"] or "{}"),
            "ip": r["ip"], "result": r["result"], "created_at": r["created_at"],
        }
        for r in rows
    ]