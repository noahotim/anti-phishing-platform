"""User management (admins) and audit log access (admins)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import database
from ..audit import audit
from ..hashing import hash_password
from ..security import (
    CurrentUser,
    client_ip,
    revoke_all_sessions_for_user,
    require_admin,
    require_super_admin,
)

router = APIRouter(prefix="/api/users", tags=["users"])

VALID_ROLES = ("EMPLOYEE", "SECURITY_ANALYST", "ADMIN", "SUPER_ADMIN")


class UserIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    full_name: str = Field(default="", max_length=120)
    role: str = Field(default="EMPLOYEE")
    password: str = Field(min_length=10, max_length=512)
    status: str = Field(default="ACTIVE")


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=120)
    role: Optional[str] = None
    status: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=10, max_length=512)


def _user_dict(row) -> dict:
    return {
        "id": row["id"], "org_id": row["org_id"], "email": row["email"],
        "full_name": row["full_name"], "role": row["role"], "status": row["status"],
        "created_at": row["created_at"], "last_login_at": row["last_login_at"],
    }


@router.get("")
def list_users(
    user: CurrentUser = Depends(require_admin),
    role: Optional[str] = Query(default=None),
):
    if role:
        rows = database.fetchall(
            "SELECT * FROM users WHERE org_id=? AND role=? ORDER BY id",
            (user.org_id, role),
        )
    else:
        rows = database.fetchall(
            "SELECT * FROM users WHERE org_id=? ORDER BY id", (user.org_id,)
        )
    return [_user_dict(r) for r in rows]


@router.post("", status_code=201)
def create_user(
    body: UserIn,
    request: Request,
    user: CurrentUser = Depends(require_super_admin),
):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="invalid role")
    exists = database.fetchone("SELECT id FROM users WHERE lower(email)=lower(?)",
                               (body.email.strip(),))
    if exists:
        raise HTTPException(status_code=409, detail="email already registered")
    new_id = database.execute(
        """
        INSERT INTO users (org_id, email, full_name, password_hash, role, status, created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            user.org_id, body.email.strip().lower(), body.full_name.strip(),
            hash_password(body.password), body.role, body.status,
            database.utcnow_iso(),
        ),
    )
    audit(action="CREATE_USER", entity="user", entity_id=new_id,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request),
          new={"email": body.email, "role": body.role, "status": body.status})
    return _user_dict(database.fetchone("SELECT * FROM users WHERE id=?", (new_id,)))


@router.put("/{uid}")
def update_user(
    uid: int,
    body: UserUpdate,
    request: Request,
    user: CurrentUser = Depends(require_super_admin),
):
    row = database.fetchone("SELECT * FROM users WHERE id=? AND org_id=?",
                            (uid, user.org_id))
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    prev = _user_dict(row)
    if body.role and body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="invalid role")
    if body.status and body.status not in ("ACTIVE", "DISABLED"):
        raise HTTPException(status_code=400, detail="invalid status")
    database.execute(
        """
        UPDATE users SET full_name=COALESCE(?, full_name),
            role=COALESCE(?, role), status=COALESCE(?, status),
            password_hash=CASE WHEN ? IS NULL THEN password_hash ELSE ? END
        WHERE id=?
        """,
        (
            body.full_name, body.role, body.status,
            hash_password(body.password) if body.password else None,
            hash_password(body.password) if body.password else None,
            uid,
        ),
    )
    if body.status == "DISABLED":
        revoke_all_sessions_for_user(uid)
    new = dict(prev)
    if body.role:
        new["role"] = body.role
    if body.status:
        new["status"] = body.status
    audit(action="UPDATE_USER", entity="user", entity_id=uid,
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev=prev, new=new)
    return _user_dict(database.fetchone("SELECT * FROM users WHERE id=?", (uid,)))