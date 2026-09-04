"""Dashboard statistics endpoints."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .. import database
from ..security import CurrentUser, require_analyst

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _iso_days_ago(days: Optional[int]) -> str:
    from datetime import timedelta
    d = datetime.now(timezone.utc) - timedelta(days=days or 7)
    return d.isoformat(timespec="seconds")


@router.get("/statistics")
def statistics(
    user: CurrentUser = Depends(require_analyst),
    days: int = Query(default=30, ge=1, le=3650),
):
    since = _iso_days_ago(days)
    org_id = user.org_id

    total = database.fetchone(
        "SELECT COUNT(*) c FROM url_scans WHERE org_id=? AND created_at>=?",
        (org_id, since),
    )["c"]
    grouped = database.fetchall(
        """
        SELECT classification, COUNT(*) c FROM url_scans
        WHERE org_id=? AND created_at>=? GROUP BY classification
        """,
        (org_id, since),
    )
    counts = {r["classification"]: r["c"] for r in grouped}

    blocked = database.fetchone(
        "SELECT COUNT(*) c FROM url_scans WHERE org_id=? AND created_at>=? "
        "AND classification IN ('MALICIOUS','SUSPICIOUS')",
        (org_id, since),
    )["c"]

    # top impersonated domains
    top_imp = database.fetchall(
        """
        SELECT COALESCE(matched_domain, 'none') AS domain, COUNT(*) c
        FROM url_scans
        WHERE org_id=? AND created_at>=? AND classification IN ('MALICIOUS','SUSPICIOUS')
        GROUP BY matched_domain ORDER BY c DESC LIMIT 10
        """,
        (org_id, since),
    )

    # risk score distribution buckets
    dist = []
    buckets = [(0, 20, "0-20"), (21, 50, "21-50"), (51, 75, "51-75"), (76, 100, "76-100")]
    for lo, hi, label in buckets:
        c = database.fetchone(
            "SELECT COUNT(*) c FROM url_scans WHERE org_id=? AND created_at>=? "
            "AND risk_score>=? AND risk_score<=?",
            (org_id, since, lo, hi),
        )["c"]
        dist.append({"label": label, "count": c})

    # recent scans
    recent = database.fetchall(
        "SELECT id, url, classification, risk_score, matched_domain, source, created_at "
        "FROM url_scans WHERE org_id=? ORDER BY id DESC LIMIT 15",
        (org_id,),
    )

    # source mix
    sources = database.fetchall(
        "SELECT source, COUNT(*) c FROM url_scans WHERE org_id=? AND created_at>=? "
        "GROUP BY source",
        (org_id, since),
    )

    # reports by status
    rep_by_status = database.fetchall(
        "SELECT status, COUNT(*) c FROM threat_reports WHERE org_id=? AND created_at>=? "
        "GROUP BY status",
        (org_id, since),
    )

    # live threat-intel feed status
    from ..services.ti_sync import get_sync_status
    ti = get_sync_status(org_id)
    ti_count = ti["total_known_threats"]
    ti_sources = database.fetchone(
        "SELECT COUNT(DISTINCT source) c FROM known_threats WHERE org_id=?",
        (org_id,),
    )["c"]

    # daily trend (last N days)
    from datetime import timedelta
    trend = []
    today = datetime.now(timezone.utc).date()
    for offset in range(max(1, min(90, days)) - 1, -1, -1):
        day = today - timedelta(days=offset)
        iso = day.strftime("%Y-%m-%d")
        row = database.fetchone(
            """
            SELECT COUNT(*) c,
                   SUM(CASE WHEN classification IN ('MALICIOUS','SUSPICIOUS') THEN 1 ELSE 0 END) bad
            FROM url_scans WHERE org_id=? AND substr(created_at,1,10)=?
            """,
            (org_id, iso),
        )
        trend.append({
            "date": iso,
            "total": row["c"],
            "blocked": row["bad"] or 0,
        })

    return {
        "days": days,
        "total_scans": total,
        "safe": counts.get("SAFE", 0),
        "suspicious": counts.get("SUSPICIOUS", 0),
        "malicious": counts.get("MALICIOUS", 0),
        "unknown": counts.get("UNKNOWN", 0),
        "blocked": blocked,
        "top_impersonated": [
            {"domain": r["domain"], "count": r["c"]} for r in top_imp
        ],
        "risk_distribution": dist,
        "recent_scans": [dict(r) for r in recent],
        "sources": [{"source": r["source"], "count": r["c"]} for r in sources],
        "reports_by_status": [
            {"status": r["status"], "count": r["c"]} for r in rep_by_status
        ],
        "threat_intel": {
            "known_threats": ti_count,
            "sources": ti_sources,
            "last_sync": ti["last_sync"],
        },
        "trend": trend,
    }