"""Live threat-intelligence feed sync (keyless).

Pulls fresh malicious hosts from the public abuse.ch URLhaus host file into the
organisation's `known_threats` table so every scan is checked against
real, recently-active phishing/malware infrastructure.

The sync is best-effort: any failure (network, timeout, parsing) is reported
back to the caller and never crashes the app.  Manual/source rows are always
preserved; only feed rows are evicted when the table exceeds its cap.
"""
from __future__ import annotations

import json
import logging
from typing import Callable, Optional

from .. import database
from .threat_intel import fetch_urlhaus_hostfile

log = logging.getLogger("ti_sync")

FEED_SOURCE = "URLHAUS_FEED"
_MANUAL = "MANUAL"

_INSERT = """
INSERT OR IGNORE INTO known_threats
    (org_id, domain, note, source, created_at)
VALUES (?,?,?,?,?)
"""


def insert_hosts(
    org_id: int,
    hosts: list[str],
    max_total: Optional[int],
    source: str = FEED_SOURCE,
) -> tuple[int, int]:
    """Insert hosts; returns (added, total_known_threats)."""
    max_total = max_total if max_total and max_total > 0 else 100_000
    now = database.utcnow_iso()
    unique = list(dict.fromkeys(h for h in hosts if h and "." in h))
    added = 0
    if unique:
        present = {
            h for h in unique
            if database.fetchone(
                "SELECT id FROM known_threats WHERE org_id=? AND domain=? AND source=?",
                (org_id, h, source),
            )
        }
        fresh = [h for h in unique if h not in present]
        if fresh:
            rows = [(org_id, h, "Imported from live threat feed", source, now)
                    for h in fresh]
            database.execute_many(_INSERT, rows)
            added = len(fresh)
    _evict_to_cap(org_id, max_total, source)
    total = database.fetchone(
        "SELECT COUNT(*) c FROM known_threats WHERE org_id=?", (org_id,)
    )["c"]
    return added, total


def _evict_to_cap(org_id: int, max_total: int, source: str) -> None:
    total = database.fetchone(
        "SELECT COUNT(*) c FROM known_threats WHERE org_id=?", (org_id,)
    )["c"]
    if total <= max_total:
        return
    excess = total - max_total
    database.execute(
        """
        DELETE FROM known_threats
        WHERE id IN (
            SELECT id FROM known_threats
            WHERE org_id=? AND source=?
            ORDER BY id ASC
            LIMIT ?
        )
        """,
        (org_id, source, excess),
    )


def sync_live_feed_once(
    fetch: Optional[Callable[[int], list[str]]] = None,
    max_items: int = 5000,
    org_id: int = 1,
    max_total: int = 100_000,
) -> dict:
    """Run one sync pass. `fetch` is injectable for offline tests."""
    fetcher = fetch or fetch_urlhaus_hostfile
    try:
        hosts = fetcher(max_items)
    except Exception as exc:  # feed is best-effort
        log.warning("live feed fetch failed: %s", exc)
        return {"ok": False, "error": str(exc)[:300]}
    added, total = insert_hosts(org_id, hosts, max_total)
    last = database.utcnow_iso()
    database.execute(
        """
        INSERT INTO system_settings (org_id, key, value, updated_by, updated_at)
        VALUES (?, 'ti_last_sync', ?, NULL, ?)
        ON CONFLICT(org_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """,
        (org_id, json.dumps({"at": last, "source": FEED_SOURCE,
                             "fetched": len(hosts), "added": added, "total": total}),
         last),
    )
    log.info(
        "live feed sync: fetched=%d added=%d total=%d", len(hosts), added, total
    )
    return {
        "ok": True,
        "source": FEED_SOURCE,
        "fetched": len(hosts),
        "added": added,
        "total_known_threats": total,
        "last_sync": last,
    }


def get_sync_status(org_id: int) -> dict:
    total = database.fetchone(
        "SELECT COUNT(*) c FROM known_threats WHERE org_id=?", (org_id,)
    )["c"]
    row = database.fetchone(
        "SELECT value FROM system_settings WHERE org_id=? AND key='ti_last_sync'",
        (org_id,),
    )
    last: Optional[str] = None
    if row:
        try:
            last = json.loads(row["value"]).get("at")
        except (TypeError, json.JSONDecodeError):
            last = None
    return {"total_known_threats": total, "last_sync": last}