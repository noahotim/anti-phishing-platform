"""Anonymous rule feed for browser-guard integrations.

Publishes the minimal set of blocked domains that the PhishGuard browser
extension needs for instant, network-layer blocking: manually blocked sites
and the seed demos. Only categories currently active in the org content policy
are included (uncategorized rows are unconditional). The long tail
(URLHAUS_FEED + fuzzy/typosquat matches) is covered by the extension's
per-navigation precheck instead.
"""
from __future__ import annotations

from fastapi import APIRouter, Query

from .. import database
from ..content_policy import CATEGORY_LABELS

router = APIRouter(prefix="/api/guard", tags=["guard"])


@router.get("/rules")
def guard_rules(org_id: int = Query(default=1, ge=1)):
    active = set(database.Config.get_content_policy(org_id))
    rows = database.fetchall(
        """
        SELECT domain, category
        FROM known_threats
        WHERE org_id=? AND source IN ('MANUAL','SEED')
        ORDER BY domain
        """,
        (org_id,),
    )
    rules = []
    for r in rows:
        category = r["category"] or ""
        # Unconditional malware always blocks; categorized rows only while the
        # category is active in the content policy.
        if category and category not in active:
            continue
        label = CATEGORY_LABELS.get(category, "Malware") if category else "Malware"
        rules.append({
            "domain": r["domain"],
            "category": category or None,
            "label": label,
        })
    return {
        "org": org_id,
        "active_categories": sorted(active),
        "rules": rules,
        "generated_at": database.utcnow_iso(),
    }