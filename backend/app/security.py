"""Authentication, sessions, and role-based access control.

Model: stateless bearer tokens are NOT used; sessions are stored server-side in
the sessions table (revocable, expiring).  No authentication cookies are
dropped by default, so classic CSRF is not applicable to the JSON API — tokens
travel in the Authorization header (see CSRF notes in SECURITY.md).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import database
from .config import settings
from .hashing import generate_record_id

ROLE_HIERARCHY = ("EMPLOYEE", "SECURITY_ANALYST", "ADMIN", "SUPER_ADMIN")

_bearer = HTTPBearer(auto_error=False)


@dataclass
class CurrentUser:
    id: int
    org_id: int
    email: str
    full_name: str
    role: str
    status: str

    @property
    def is_super_admin(self) -> bool:
        return self.role == "SUPER_ADMIN"

    def can(self, min_role: str) -> bool:
        try:
            return ROLE_HIERARCHY.index(self.role) >= ROLE_HIERARCHY.index(min_role)
        except ValueError:
            return False


def create_session(user_id: int, ip: str = "", user_agent: str = "") -> str:
    token = generate_record_id()
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.token_ttl_hours)
    database.execute(
        """
        INSERT INTO sessions (id, user_id, expires_at, created_at, ip, user_agent)
        VALUES (?,?,?,?,?,?)
        """,
        (token, user_id, expires.isoformat(timespec="seconds"),
         database.utcnow_iso(), ip, user_agent),
    )
    database.execute(
        "UPDATE users SET last_login_at=? WHERE id=?",
        (database.utcnow_iso(), user_id),
    )
    return token


def revoke_session(token: str) -> None:
    database.execute("DELETE FROM sessions WHERE id=?", (token,))


def revoke_all_sessions_for_user(user_id: int) -> None:
    database.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def load_user_by_email(email: str) -> Optional[database.sqlite3.Row]:
    return database.fetchone(
        "SELECT * FROM users WHERE lower(email)=lower(?)", (email.strip(),)
    )


def load_user(id: int) -> Optional[database.sqlite3.Row]:
    return database.fetchone("SELECT * FROM users WHERE id=?", (id,))


def _current_user_from_token(token: str) -> CurrentUser:
    row = database.fetchone(
        """
        SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.id=? AND s.expires_at > ?
        """,
        (token, datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session expired or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if row["status"] != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="account disabled"
        )
    return CurrentUser(
        id=row["id"],
        org_id=row["org_id"],
        email=row["email"],
        full_name=row["full_name"],
        role=row["role"],
        status=row["status"],
    )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _current_user_from_token(credentials.credentials)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[CurrentUser]:
    if credentials is None or not credentials.credentials:
        return None
    try:
        return _current_user_from_token(credentials.credentials)
    except HTTPException:
        return None


def require_role(*roles: str):
    async def checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires one of roles: {', '.join(roles)}",
            )
        return user

    return checker


require_analyst = require_role("SECURITY_ANALYST", "ADMIN", "SUPER_ADMIN")
require_admin = require_role("ADMIN", "SUPER_ADMIN")
require_super_admin = require_role("SUPER_ADMIN")


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"