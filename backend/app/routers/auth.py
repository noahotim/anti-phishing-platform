"""Authentication endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import database
from ..audit import audit
from ..hashing import verify_password
from ..security import (
    CurrentUser,
    client_ip,
    create_session,
    get_current_user,
    revoke_session,
    revoke_all_sessions_for_user,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=512)


class LoginResponse(BaseModel):
    token: str
    user: dict


@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, request: Request):
    user = database.fetchone(
        "SELECT * FROM users WHERE lower(email)=lower(?)", (req.email.strip(),)
    )
    ok = user is not None and verify_password(req.password, user["password_hash"])
    if not ok:
        audit(action="AUTH_FAILED", actor_email=req.email, ip=client_ip(request),
              result="FAIL")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
        )
    if user["status"] != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="account disabled"
        )
    token = create_session(
        user["id"], ip=client_ip(request), user_agent=request.headers.get("user-agent", "")
    )
    audit(action="LOGIN", actor_id=user["id"], actor_email=user["email"],
          org_id=user["org_id"], ip=client_ip(request),
          user_agent=request.headers.get("user-agent", ""))
    return LoginResponse(
        token=token,
        user={
            "id": user["id"], "email": user["email"],
            "full_name": user["full_name"], "role": user["role"],
            "org_id": user["org_id"],
        },
    )


@router.post("/logout")
def logout(request: Request, user: CurrentUser = Depends(get_current_user)):
    auth = request.headers.get("authorization", "")
    token = auth.replace("Bearer ", "") if auth else ""
    if token:
        revoke_session(token)
    audit(action="LOGOUT", actor_id=user.id, actor_email=user.email,
          org_id=user.org_id, ip=client_ip(request))
    return {"detail": "logged out"}


@router.get("/me")
def me(user: CurrentUser = Depends(get_current_user)):
    return {
        "id": user.id, "email": user.email, "full_name": user.full_name,
        "role": user.role, "org_id": user.org_id,
    }