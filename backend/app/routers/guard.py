"""Anonymous rule feed for browser-guard integrations.

Publishes the minimal set of blocked domains that the PhishGuard browser
extension needs for instant, network-layer blocking: manually blocked sites
and the seed demos. Only categories currently active in the org content policy
are included (uncategorized rows are unconditional). The long tail
(URLHAUS_FEED + fuzzy/typosquat matches) is covered by the extension's
per-navigation precheck instead.
"""
from __future__ import annotations

import json
import pathlib

from fastapi import APIRouter, Query

from .. import database
from ..content_policy import CATEGORY_LABELS

router = APIRouter(prefix="/api/guard", tags=["guard"])


@router.get("/rules")
def guard_rules(org_id: int = Query(default=1, ge=1)):
    active = set(database.Config.get_content_policy(org_id)) | {"GAMBLING"}
    rows = database.fetchall(
        """
        SELECT domain, category
        FROM known_threats
        WHERE org_id=? AND source IN ('MANUAL','SEED')
        ORDER BY domain
        """,
        (org_id,),
    )
    # Whitelisted domains never appear in the rule feed: otherwise the
    # extension keeps instant-blocking a site the user just approved, because
    # its DNR rules and local threat list are built from this endpoint alone.
    trusted = [
        (r["normalized_domain"] or "").lower().rstrip(".")
        for r in database.fetchall(
            "SELECT normalized_domain FROM trusted_domains WHERE org_id=?",
            (org_id,),
        )
    ]
    trusted = [t for t in trusted if t]

    def suppressed(domain: str) -> bool:
        d = (domain or "").lower().rstrip(".")
        if not d:
            return False
        for t in trusted:
            # Exact entry, a threat under a whitelisted apex, or a threat
            # apex containing the whitelisted host (the precheck layer still
            # decides subdomain-by-subdomain in that case).
            if d == t or d.endswith("." + t) or t.endswith("." + d):
                return True
        return False

    rules = []
    for r in rows:
        if suppressed(r["domain"]):
            continue
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
        "trusted": trusted,
        "rules": rules,
        "generated_at": database.utcnow_iso(),
    }


@router.get("/version")
def guard_version():
    """Latest guard version for auto-update checks. Already installed guards poll this."""
    # The manifest is not always next to the backend (Docker copies it to /app/extension),
    # so try every known location before falling back.
    here = pathlib.Path(__file__).resolve()
    candidates = [
        here.parent.parent.parent.parent / "extension" / "manifest.json",
        here.parent.parent.parent / "extension" / "manifest.json",
        pathlib.Path("/app/extension/manifest.json"),
        pathlib.Path("/app/frontend/extension/manifest.json"),
        pathlib.Path.cwd() / "extension" / "manifest.json",
    ]
    ver = "0.0.0"
    name = "BOTIMPHISHGUARD"
    for manifest_path in candidates:
        try:
            if manifest_path.exists():
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                ver = data.get("version") or ver
                name = data.get("name") or name
                break
        except Exception:
            continue
    return {
        "version": ver,
        "name": name,
        "update_url": "https://phishguard-8vri.onrender.com/app/install.html",
        "firefox_url": "https://github.com/noahotim/anti-phishing-platform/releases/latest/download/phishguard-firefox-signed.xpi",
        "chrome_url": "https://github.com/noahotim/anti-phishing-platform/releases/latest/download/phishguard-chrome.zip",
    }