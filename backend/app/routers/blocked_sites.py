"""Blocked-site management: the org's blacklist plus content-policy categories.

A blocked site is stored in `known_threats`. Uncategorized entries are treated
as confirmed malware for every scan. Entries with a category (e.g. GAMBLING)
are only enforced while that category is active in the content policy, which
lets an organisation block betting/adult sites org-wide and lift them later.
"""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field

from .. import database
from ..audit import audit
from ..content_policy import CONTENT_CATEGORIES
from ..security import CurrentUser, client_ip, require_admin
from ..services import normalization

router = APIRouter(prefix="/api/blocked-sites", tags=["blocked-sites"])


class BlockedSiteIn(BaseModel):
    domain: str = Field(min_length=2, max_length=253)
    category: str = Field(default="", max_length=32)
    note: str = Field(default="", max_length=2000)


def _normalize_category(cat: str) -> str:
    cat = (cat or "").strip().upper().replace(" ", "_")
    return "" if cat in ("", "MALWARE", "NONE") else cat


def _valid_category(cat: str) -> bool:
    return cat == "" or cat in CONTENT_CATEGORIES


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "org_id": row["org_id"],
        "domain": row["domain"],
        "category": row["category"] or "",
        "note": row["note"],
        "source": row["source"],
        "created_at": row["created_at"],
    }


@router.get("")
def list_blocked_sites(
    user: CurrentUser = Depends(require_admin),
    category: str = Query(default="", max_length=32),
    source: str = Query(default="", max_length=32),
):
    sql = "SELECT * FROM known_threats WHERE org_id=?"
    params: list = [user.org_id]
    if category:
        sql += " AND category=?"
        params.append(_normalize_category(category))
    if source:
        sql += " AND source=?"
        params.append(source)
    sql += " ORDER BY domain"
    return [_row_to_dict(r) for r in database.fetchall(sql, tuple(params))]


@router.post("", status_code=201)
def create_blocked_site(
    body: BlockedSiteIn,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    norm = normalization.to_ascii(body.domain)
    if not norm or "." not in norm:
        raise HTTPException(status_code=422, detail="invalid domain")
    category = _normalize_category(body.category)
    if not _valid_category(category):
        raise HTTPException(
            status_code=400,
            detail="unknown category; use " + ", ".join(CONTENT_CATEGORIES),
        )
    exists = database.fetchone(
        "SELECT id FROM known_threats WHERE org_id=? AND domain=?",
        (user.org_id, norm),
    )
    if exists:
        raise HTTPException(status_code=409, detail="domain already blocked")
    new_id = database.execute(
        """
        INSERT INTO known_threats (org_id, domain, note, source, category, created_at)
        VALUES (?,?,?,?,?,?)
        """,
        (
            user.org_id, norm, body.note.strip(), "MANUAL", category,
            database.utcnow_iso(),
        ),
    )
    audit(action="CREATE_BLOCKED_SITE", entity="blocked_site", entity_id=new_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), new=body.model_dump())
    return _row_to_dict(
        database.fetchone("SELECT * FROM known_threats WHERE id=?", (new_id,))
    )


@router.put("/{site_id}")
def update_blocked_site(
    site_id: int,
    body: BlockedSiteIn,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    row = database.fetchone(
        "SELECT * FROM known_threats WHERE id=? AND org_id=?",
        (site_id, user.org_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="site not found")
    category = _normalize_category(body.category)
    if not _valid_category(category):
        raise HTTPException(
            status_code=400,
            detail="unknown category; use " + ", ".join(CONTENT_CATEGORIES),
        )
    prev = _row_to_dict(row)
    database.execute(
        "UPDATE known_threats SET note=?, category=? WHERE id=?",
        (body.note.strip(), category, site_id),
    )
    audit(action="UPDATE_BLOCKED_SITE", entity="blocked_site", entity_id=site_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev=prev, new=body.model_dump())
    return _row_to_dict(
        database.fetchone("SELECT * FROM known_threats WHERE id=?", (site_id,))
    )


@router.delete("/{site_id}")
def delete_blocked_site(
    site_id: int,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    row = database.fetchone(
        "SELECT * FROM known_threats WHERE id=? AND org_id=?",
        (site_id, user.org_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="site not found")
    database.execute("DELETE FROM known_threats WHERE id=?", (site_id,))
    audit(action="DELETE_BLOCKED_SITE", entity="blocked_site", entity_id=site_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev=_row_to_dict(row))
    return {"detail": "deleted"}


@router.post("/import")
async def import_blocked_sites(
    request: Request,
    user: CurrentUser = Depends(require_admin),
    file: UploadFile = File(...),
):
    """Bulk import. CSV columns: domain[,category[,note]] (header optional)."""
    raw = await file.read()
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    added, skipped = 0, 0
    errors: list[str] = []
    seen_domains: set[str] = set()
    for lineno, cells in enumerate(reader, start=1):
        cells = [c.strip() for c in cells]
        if not cells or not cells[0]:
            continue
        domain = cells[0]
        category = _normalize_category(cells[1]) if len(cells) > 1 else ""
        note = cells[2] if len(cells) > 2 else ""
        if lineno == 1 and domain.lower() == "domain":
            continue  # header row
        norm = normalization.to_ascii(domain)
        if not norm or "." not in norm:
            errors.append(f"line {lineno}: invalid domain '{(domain or '')[:80]}'")
            continue
        if not _valid_category(category):
            errors.append(
                f"line {lineno}: invalid category '{(category or '')[:80]}'"
            )
            continue
        if norm in seen_domains:
            skipped += 1
            continue
        seen_domains.add(norm)
        exists = database.fetchone(
            "SELECT id FROM known_threats WHERE org_id=? AND domain=?",
            (user.org_id, norm),
        )
        if exists:
            skipped += 1
            continue
        database.execute(
            """
            INSERT INTO known_threats (org_id, domain, note, source, category, created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (user.org_id, norm, note, "MANUAL", category, database.utcnow_iso()),
        )
        added += 1
    audit(action="IMPORT_BLOCKED_SITES", entity="blocked_site",
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request),
          new={"added": added, "skipped": skipped, "errors": errors[:20]})
    return {"added": added, "skipped": skipped, "errors": errors[:50]}