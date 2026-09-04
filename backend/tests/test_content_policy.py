"""Content-policy blocking (gambling / adult …) and blocked-site management."""
from __future__ import annotations

import io


def _scan(client, headers, url):
    r = client.post("/api/analyze/url", json={"url": url}, headers=headers)
    return r


def test_blocked_sites_seeded(client, super_headers):
    r = client.get("/api/blocked-sites", headers=super_headers)
    assert r.status_code == 200
    rows = {x["domain"]: x for x in r.json()}
    assert rows["bet-demo-casino.com"]["category"] == "GAMBLING"
    assert rows["adult-demo-content.net"]["category"] == "ADULT"
    assert rows["paypa1-secure.com"]["category"] == ""


def test_create_duplicate_invalid(client, super_headers):
    body = {"domain": "casino-xpay-999.com", "category": "GAMBLING", "note": "betting"}
    r = client.post("/api/blocked-sites", json=body, headers=super_headers)
    assert r.status_code == 201
    assert r.json()["category"] == "GAMBLING"
    dup = client.post("/api/blocked-sites", json=body, headers=super_headers)
    assert dup.status_code == 409
    bad = client.post("/api/blocked-sites",
                      json={"domain": "noT-A-valid---domain!!", "category": "GAMBLING"},
                      headers=super_headers)
    assert bad.status_code == 422
    unbranded = client.post("/api/blocked-sites",
                            json={"domain": "thing.com", "category": "BOGUS_CAT"},
                            headers=super_headers)
    assert unbranded.status_code == 400


def test_gambling_site_is_blocked_in_scanner(client, super_headers):
    client.post("/api/blocked-sites",
                json={"domain": "casino-xyz-policy.com", "category": "GAMBLING"},
                headers=super_headers)
    r = _scan(client, super_headers, "https://casino-xyz-policy.com/promo")
    assert r.status_code == 200
    d = r.json()
    assert d["classification"] == "MALICIOUS"
    assert d["risk_score"] == 100
    assert d["content_blocked"] is True
    assert d["blocked_category"] == "GAMBLING"
    assert any("policy" in x.lower() and "GAMBLING" in x for x in d["reasons"])


def test_disabling_category_lifts_the_block(client, super_headers):
    client.post("/api/blocked-sites",
                json={"domain": "adult-xyz-policy.org", "category": "ADULT"},
                headers=super_headers)
    blocked = _scan(client, super_headers, "https://adult-xyz-policy.org/").json()
    assert blocked["content_blocked"] is True
    assert blocked["blocked_category"] == "ADULT"

    r = client.put("/api/settings/content-policy", json={"categories": ["GAMBLING"]},
                   headers=super_headers)
    assert r.status_code == 200
    try:
        lifted = _scan(client, super_headers, "https://adult-xyz-policy.org/").json()
        assert lifted["content_blocked"] is False
        assert lifted["blocked_category"] is None
        assert lifted["classification"] != "MALICIOUS"
        assert not any("policy" in x.lower() for x in lifted["reasons"])
    finally:
        client.put("/api/settings/content-policy",
                   json={"categories": ["GAMBLING", "ADULT"]},
                   headers=super_headers)


def test_content_policy_settings_validation(client, super_headers):
    ok = client.put("/api/settings/content-policy", json={"categories": ["SOCIAL_MEDIA"]},
                    headers=super_headers)
    assert ok.status_code == 200
    got = client.get("/api/settings/content-policy", headers=super_headers)
    assert got.json() == ["SOCIAL_MEDIA"]
    client.put("/api/settings/content-policy",
               json={"categories": ["GAMBLING", "ADULT"]}, headers=super_headers)
    bad = client.put("/api/settings/content-policy", json={"categories": ["NOPE"]},
                     headers=super_headers)
    assert bad.status_code == 400


def test_update_and_delete_blocked_site(client, super_headers):
    site = client.post("/api/blocked-sites",
                       json={"domain": "temp-block-xyz.com", "category": "OTHER"},
                       headers=super_headers).json()
    up = client.put(f"/api/blocked-sites/{site['id']}",
                    json={"domain": "temp-block-xyz.com", "category": "ADULT",
                          "note": "re-categorised"},
                    headers=super_headers)
    assert up.status_code == 200
    assert up.json()["category"] == "ADULT"

    still = _scan(client, super_headers, "https://temp-block-xyz.com/").json()
    assert still["blocked_category"] == "ADULT"
    still["content_blocked"] is True

    cl = client.delete(f"/api/blocked-sites/{site['id']}", headers=super_headers)
    assert cl.status_code == 200
    gone = _scan(client, super_headers, "https://temp-block-xyz.com/").json()
    assert gone["content_blocked"] is False


def test_import_csv(client, super_headers):
    csv_body = (
        "domain,category,note\n"
        "imported-game-xyz.com,GAMBLING,\n"
        "imported-adult-xyz.net,ADULT,legacy\n"
        "bogus-domain,OTHER,no dot -> skipped\n"
    )
    r = client.post(
        "/api/blocked-sites/import",
        files={"file": ("sites.csv", io.BytesIO(csv_body.encode("utf-8")),
                        "text/csv")},
        headers=super_headers,
    )
    assert r.status_code == 200
    result = r.json()
    assert result["added"] == 2
    assert len(result["errors"]) == 1

    blocked = _scan(client, super_headers, "https://imported-game-xyz.com/")
    assert blocked.json()["blocked_category"] == "GAMBLING"


def test_uncategorized_entry_is_always_malware(client, super_headers):
    client.post("/api/blocked-sites",
                json={"domain": "plain-malware-xyz.com", "category": ""},
                headers=super_headers)
    r = _scan(client, super_headers, "https://plain-malware-xyz.com/")
    d = r.json()
    assert d["classification"] == "MALICIOUS"
    assert d["content_blocked"] is False  # malware, not policy
    assert any("threat" in x.lower() for x in d["reasons"])