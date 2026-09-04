"""Threat-intelligence feed status and on-demand sync (admins)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..audit import audit
from ..config import settings as app_settings
from ..security import CurrentUser, client_ip, require_admin
from ..services.ti_sync import get_sync_status, sync_live_feed_once

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


@router.get("")
def threat_intel_status(user: CurrentUser = Depends(require_admin)):
    status = get_sync_status(user.org_id)
    return {
        "enabled": app_settings.ti_sync_enabled,
        "feed": "URLhaus (abuse.ch) hostfile — keyless",
        "sync_interval_minutes": app_settings.ti_sync_interval_min,
        "max_items_per_sync": app_settings.ti_sync_max_items,
        "known_threats": status["total_known_threats"],
        "last_sync": status["last_sync"],
        "per_scan_providers_enabled": app_settings.enable_external_ti,
    }


@router.post("/sync")
def threat_intel_sync_now(
    request: Request,
    user: CurrentUser = Depends(require_admin),
):
    import json

    result = sync_live_feed_once(
        max_items=app_settings.ti_sync_max_items,
        org_id=user.org_id,
        max_total=app_settings.ti_sync_max_total,
    )
    audit(action="SYNC_THREAT_INTEL", entity="threat_intel",
          org_id=user.org_id, actor_id=user.id, actor_email=user.email,
          ip=client_ip(request), new=json.loads(json.dumps(result, default=str)))
    return result