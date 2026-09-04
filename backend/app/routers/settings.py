"""System settings: risk thresholds (configurable by admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from .. import database
from ..audit import audit
from ..security import CurrentUser, client_ip, require_admin

router = APIRouter(prefix="/api/settings", tags=["settings"])


class ThresholdsIn(BaseModel):
    low: int = Field(default=20, ge=0, le=49)
    moderate: int = Field(default=50, ge=1, le=74)
    high: int = Field(default=75, ge=2, le=99)


@router.get("/risk-thresholds")
def get_thresholds(user: CurrentUser = Depends(require_admin)):
    return database.Config.get_risk_thresholds(user.org_id)


@router.put("/risk-thresholds")
def update_thresholds(
    body: ThresholdsIn,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    if not (body.low < body.moderate < body.high):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="low < moderate < high required")
    prev = database.Config.set_risk_thresholds(
        user.org_id, body.model_dump(), user.id
    )
    audit(action="UPDATE_RISK_THRESHOLDS", entity="system_settings",
          entity_id=f"risk_thresholds:{user.org_id}",
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev={"value": prev}, new=body.model_dump())
    return body.model_dump()


class ContentPolicyIn(BaseModel):
    categories: list[str] = Field(default_factory=list, max_length=16)


class WhitelistOnlyIn(BaseModel):
    enabled: bool


@router.get("/whitelist-only")
def get_whitelist_only(user: CurrentUser = Depends(require_admin)):
    return {"enabled": database.Config.get_whitelist_only(user.org_id)}


@router.put("/whitelist-only")
def update_whitelist_only(
    body: WhitelistOnlyIn,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    prev = database.Config.set_whitelist_only(user.org_id, bool(body.enabled), user.id)
    audit(action="UPDATE_WHITELIST_ONLY", entity="system_settings",
          entity_id=f"whitelist_only:{user.org_id}",
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev={"value": prev}, new={"enabled": bool(body.enabled)})
    return {"enabled": bool(body.enabled)}


@router.get("/content-policy")
def get_content_policy(user: CurrentUser = Depends(require_admin)):
    return database.Config.get_content_policy(user.org_id)


@router.put("/content-policy")
def update_content_policy(
    body: ContentPolicyIn,
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    from fastapi import HTTPException
    from ..content_policy import CONTENT_CATEGORIES

    normalized = list(dict.fromkeys(
        c.strip().upper().replace(" ", "_") for c in body.categories
    ))
    invalid = [c for c in normalized if c not in CONTENT_CATEGORIES]
    if invalid:
        raise HTTPException(status_code=400, detail=f"unknown categories: {invalid}")
    prev = database.Config.set_content_policy(user.org_id, normalized, user.id)
    audit(action="UPDATE_CONTENT_POLICY", entity="system_settings",
          entity_id=f"content_policy:{user.org_id}",
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), prev={"value": prev}, new={"categories": normalized})
    return normalized