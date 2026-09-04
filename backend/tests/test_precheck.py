"""Browser-guard endpoints: anonymous precheck + guard rules (extension)."""
from __future__ import annotations

from app import database


def _precheck(client, url):
    return client.post("/api/analyze/precheck", json={"url": url})


def test_precheck_anonymous_ok(client):
    r = client.post("/api/analyze/precheck", json={"url": "https://www.google.com/"})
    assert r.status_code == 200
    d = r.json()
    assert d["classification"] in ("SAFE", "MALICIOUS", "SUSPICIOUS", "UNKNOWN")
    assert d["blocked"] is False
    assert "risk_score" in d


def test_precheck_blocks_known_malware_without_writing_scan(client):
    before = database.fetchone(
        "SELECT COUNT(*) AS c FROM url_scans WHERE org_id=1"
    )["c"]
    r = _precheck(client, "https://paypa1-secure.com/login")
    assert r.status_code == 200
    d = r.json()
    assert d["blocked"] is True
    assert d["classification"] == "MALICIOUS"
    assert d["risk_score"] == 100
    after = database.fetchone(
        "SELECT COUNT(*) AS c FROM url_scans WHERE org_id=1"
    )["c"]
    assert after == before  # precheck never persists


def test_precheck_blocks_active_policy_category(client, super_headers):
    client.post("/api/blocked-sites",
                json={"domain": "guard-casino-test.com", "category": "GAMBLING"},
                headers=super_headers)
    r = _precheck(client, "https://guard-casino-test.com/")
    d = r.json()
    assert d["blocked"] is True
    assert d["content_blocked"] is True
    assert d["blocked_category"] == "GAMBLING"
    assert d["blocked_label"] == "Gambling / betting"
    assert d["blocked_reason"] and "policy" in d["blocked_reason"].lower()


def test_precheck_respects_lifted_category(client, super_headers):
    client.post("/api/blocked-sites",
                json={"domain": "guard-adult-test.com", "category": "ADULT"},
                headers=super_headers)
    assert _precheck(client, "https://guard-adult-test.com/").json()["blocked"] is True
    r = client.put("/api/settings/content-policy",
                   json={"categories": ["GAMBLING"]}, headers=super_headers)
    assert r.status_code == 200
    try:
        assert _precheck(client, "https://guard-adult-test.com/").json()["blocked"] is False
    finally:
        client.put("/api/settings/content-policy",
                   json={"categories": ["GAMBLING", "ADULT"]}, headers=super_headers)


def test_precheck_requires_url(client):
    assert client.post("/api/analyze/precheck", json={"url": "   "}).status_code == 422


def test_guard_rules_anonymous_and_filtered(client, super_headers):
    client.post("/api/blocked-sites",
                json={"domain": "guard-rule-on.com", "category": "GAMBLING"},
                headers=super_headers)
    client.post("/api/blocked-sites",
                json={"domain": "guard-rule-adult.com", "category": "ADULT"},
                headers=super_headers)
    r = client.get("/api/guard/rules")  # no auth — used by the browser extension
    assert r.status_code == 200
    rules = {x["domain"]: x for x in r.json()["rules"]}
    assert rules["bet-demo-casino.com"]["label"] == "Gambling / betting"
    assert rules["paypa1-secure.com"]["label"] == "Malware"
    assert "guard-rule-on.com" in rules         # GAMBLING active by default
    assert "guard-rule-adult.com" in rules      # ADULT active by default
    # The long-tail feed hosts are NOT published as guard rules.
    feed = database.fetchone(
        "SELECT COUNT(*) AS c FROM known_threats WHERE source='URLHAUS_FEED'"
    )["c"]
    assert feed == 0  # feed disabled in the test env