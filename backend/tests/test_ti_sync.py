"""Live feed: hostfile parsing + DB upsert (offline, no network)."""
from __future__ import annotations

from app.services.threat_intel import _parse_hostfile
from app.services import ti_sync

SAMPLE = """
################################################################
# abuse.ch URLhaus Host file                                   #
# Last updated: 2026-09-02 05:35:23 (UTC)                      #
################################################################
0.0.0.0 first-bad.com
127.0.0.1\tsecond-bad.example
127.0.0.1   second-bad.example
# comment line
this-line-is-not-a-host
0.0.0.0 third-bad.org.
"""


def test_parse_hostfile_deduplicates_and_strips():
    hosts = _parse_hostfile(SAMPLE, max_items=50)
    assert hosts == ["first-bad.com", "second-bad.example", "third-bad.org"]
    assert "this-line-is-not-a-host" not in hosts


def test_parse_hostfile_respects_cap():
    text = "\n".join(f"127.0.0.1 bad{i}.com" for i in range(20))
    assert len(_parse_hostfile(text, max_items=5)) == 5


def test_insert_hosts_adds_to_known_threats(client):
    ti_sync.insert_hosts(1, ["live-bad-xyz.com", "nope.another-xyz.net"], max_total=100)
    row = ti_sync.database.fetchone(
        "SELECT domain, source FROM known_threats WHERE domain=?",
        ("live-bad-xyz.com",),
    )
    assert row is not None
    assert row["source"] == "URLHAUS_FEED"


def test_insert_hosts_is_idempotent(client):
    hosts = ["dup-only-xyz.com"]
    a, _t = ti_sync.insert_hosts(1, hosts, max_total=100)
    b, _t2 = ti_sync.insert_hosts(1, hosts, max_total=100)
    assert a == 1 and b == 0


def test_evicts_oldest_when_over_cap(client):
    digits = 30
    hosts = [f"cap-{i}-xyz.com" for i in range(digits)]
    non_feed = ti_sync.database.fetchone(
        "SELECT COUNT(*) AS c FROM known_threats WHERE org_id=1 "
        "AND source <> 'URLHAUS_FEED'"
    )["c"]
    # Cap to exactly `non_feed + 10` rows. Only URLHAUS_FEED rows are evicted,
    # so after the pass exactly the 10 newest feed rows survive.
    added, total = ti_sync.insert_hosts(1, hosts, max_total=non_feed + 10)
    assert added == 30
    assert total == non_feed + 10
    kept = {r["domain"] for r in ti_sync.database.fetchall(
        "SELECT domain FROM known_threats WHERE org_id=1")}
    assert f"cap-{digits - 10}-xyz.com" in kept
    assert f"cap-{digits - 11}-xyz.com" not in kept
    # manually / seed-sourced rows are preserved
    assert "paypa1-secure.com" in kept
    assert "bet-demo-casino.com" in kept


def test_sync_live_feed_once_with_stub_fetcher(client):
    fetcher = lambda n: [f"stub-{i}-xyz.net" for i in range(3)]  # noqa: E731
    result = ti_sync.sync_live_feed_once(fetcher, max_items=10, org_id=1)
    assert result["ok"] is True
    assert result["added"] == 3
    assert result["total_known_threats"] >= 3


def test_sync_live_feed_once_survives_fetch_failure(client):
    def boom(_n):
        raise RuntimeError("offline")
    result = ti_sync.sync_live_feed_once(boom, org_id=1)
    assert result["ok"] is False
    assert "offline" in result["error"]