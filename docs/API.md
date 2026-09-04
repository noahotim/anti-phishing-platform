# API Reference

Base URL: `http://127.0.0.1:8000` (configurable via `HOST`/`PORT`).

Authentication: `Authorization: Bearer <token>`. Sessions are server-side and
revocable; tokens are issued by `POST /api/auth/login`.

Unless stated otherwise:

- Requests and responses are JSON.
- Errors are `{"detail": …}` (422 validation responses additionally include an
  `errors` array with `field` and `message`).
- Endpoints requiring a role return `401` without a token and `403` for an
  authenticated user with insufficient privilege.

---

## Auth

### `POST /api/auth/login`

Body:

```json
{ "email": "admin@company-example.com", "password": "ChangeMe_123!" }
```

Response `200`:

```json
{ "token": "…", "user": { "id": 1, "email": "…", "full_name": "…", "role": "SUPER_ADMIN", "org_id": 1 } }
```

Other results: `401 invalid credentials`, `403 account disabled`.

### `POST /api/auth/logout`

Revokes the presented token. Response `200 {"detail":"logged out"}`.

### `GET /api/auth/me`

Returns the current user (`id`, `email`, `full_name`, `role`, `org_id`).

---

## URL analysis

### `POST /api/analyze/url`

Optional authentication. Body: `{"url": "https://examp1e.com/login"}`.

Response `200` (abridged):

```json
{
  "url": "https://examp1e.com/login",
  "hostname": "examp1e.com",
  "registered_domain": "examp1e.com",
  "subdomain": "",
  "ascii_domain": "examp1e.com",
  "punycode_domain": "",
  "is_ip": false,
  "scheme": "https",
  "port": null,
  "username": "",
  "password": "",
  "tld": "com",
  "classification": "MALICIOUS",
  "risk_score": 63,
  "risk_level": "HIGH",
  "reasons": [
    "Destination domain is not an approved domain",
    "Domain visually matches approved domain \"example.com\" (confusable homoglyphs)"
  ],
  "signals": { "exact_match": false, "trusted_exact": false, "matched_domain": "example.com",
               "edit_distance": 0, "confusable_exact_match": true, "untrusted_destination": true },
  "content_blocked": true,
  "blocked_category": "GAMBLING",
  "matched_domain": "example.com",
  "trusted": false,
  "threat_intel": [ { "provider": "local_database", "verdict": "UNKNOWN", "score": 0 } ],
  "details": { "raw": "…", "scheme": "https", "hostname": "…", "path": "/login", "warnings": [] },
  "safe_to_visit": false
}
```

`classification` ∈ {`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`};
`risk_score` ∈ 0–100. `safe_to_visit` is true only for `SAFE` with no caveat.
When a scan is stopped by the organisation's content policy,
`content_blocked` is true, `blocked_category` names the category, and the scan
is reported as `MALICIOUS` with score 100 and a visible policy reason.

### `POST /api/analyze/precheck`

Anonymous, side-effect-free verdict used by the browser guard extension. Runs
the full detection pipeline but writes **no scan row and no audit entry**, so a
client can check every navigation cheaply. Shares the `analyze` rate-limit
bucket.

Body: `{"url": "https://examp1e.com/login"}`.

Response `200`:

```json
{
  "blocked": true,
  "content_blocked": true,
  "blocked_category": "GAMBLING",
  "blocked_label": "Gambling / betting",
  "blocked_reason": "Blocked by organization policy — GAMBLING websites are not allowed",
  "classification": "MALICIOUS",
  "risk_score": 100,
  "matched_domain": null,
  "safe_to_visit": false
}
```

`blocked` is true whenever the classification is `MALICIOUS` (threat feed,
manual block, typosquat, homoglyph, or active content-policy category).

### `GET /api/analyze/{scan_id}`

Authenticated. Returns the stored scan row plus its `threat_intel` array.
`404` if not found in the caller’s organisation.

---

## Browser guard feed

### `GET /api/guard/rules?org_id=1`

Anonymous. Returns the compact list of domains the browser extension should
block *instantly* at the network layer (manual + seed rows only, filtered to the
categories currently active in the content policy; uncategorised rows are
unconditional). The long tail (URLHAUS_FEED, fuzzy/homoglyph matches) is covered
by `POST /api/analyze/precheck` instead and is never published here.

Response `200`:

```json
{
  "org": 1,
  "active_categories": ["ADULT", "GAMBLING"],
  "generated_at": "2026-09-02T10:00:00Z",
  "rules": [
    { "domain": "adult-demo-content.net", "category": "ADULT", "label": "Adult content" },
    { "domain": "paypa1-secure.com", "category": null, "label": "Malware" }
  ]
}
```

---

## Phishing reports

### `POST /api/reports`

Authenticated. Body: `{"url": "…", "comment": "optional context"}`. Runs a full
analysis under `source=REPORT` and returns
`{"id": …, "status": "NEW", "analysis": {…}}`.

### `GET /api/reports?status=…&mine=…`

Authenticated. Employees only see their own reports; analysts/admins see
organisation-wide reports (optional `status` filter).

### `GET /api/reports/{report_id}`

Authenticated. Own report for employees; any org report for analyst+.

### `PUT /api/reports/{report_id}`

Analyst+. Body: `{"status": "…", "comment": ""}` where status ∈
`NEW | INVESTIGATING | CONFIRMED_THREAT | FALSE_POSITIVE | RESOLVED`.
Returns `{"id": …, "status": …}`.

---

## Dashboard

### `GET /api/dashboard/statistics?days=30`

Analyst+. Returns:

```json
{
  "days": 30,
  "total_scans": 32,
  "safe": 10, "suspicious": 6, "malicious": 4, "unknown": 12,
  "blocked": 10,
  "top_impersonated":  [ { "domain": "example.com", "count": 3 } ],
  "risk_distribution": [ { "label": "0-20", "count": 18 }, { "label": "21-50", "count": 9 },
                         { "label": "51-75", "count": 3 }, { "label": "76-100", "count": 2 } ],
  "recent_scans": [ { "id": 1, "url": "…", "classification": "…", "risk_score": 63,
                      "matched_domain": "…", "source": "EMPLOYEE", "created_at": "…" } ],
  "sources": [ { "source": "EMPLOYEE", "count": 20 } ],
  "reports_by_status": [ { "status": "NEW", "count": 1 } ],
  "trend": [ { "date": "2026-09-01", "total": 12, "blocked": 4 } ]
}
```

---

## Trusted domains

All require `admin`.

### `GET /api/trusted-domains?category=…`

Returns the org’s approved domains:

```json
[ { "id": 1, "org_id": 1, "domain": "example.com", "normalized_domain": "example.com",
    "category": "Corporate", "is_critical": false, "allowed_subdomains": "",
    "notes": "", "created_at": "…", "updated_at": "…" } ]
```

### `POST /api/trusted-domains`

Body:

```json
{ "domain": "maybank2u.com", "category": "Banking", "is_critical": true,
  "allowed_subdomains": "", "notes": "" }
```

`201` with the stored row. Errors: `422` invalid domain, `409` already trusted.

### `PUT /api/trusted-domains/{id}`

Same body; updates the record. `404` if absent.

### `DELETE /api/trusted-domains/{id}`

`200 {"detail":"deleted"}`.

### `POST /api/trusted-domains/import` (multipart `file`)

CSV with at least a `domain` column (optional: `category`, `is_critical`,
`allowed_subdomains`, `notes`). Returns `{"added": n, "skipped": n}`.

### `GET /api/trusted-domains/export`

Downloads `trusted_domains.csv` for the org.

### `GET /api/trusted-domains/history/{id}`

Audit history (prev/new JSON) for a single trusted domain.

---

## Audit log

All require `admin`.

### `GET /api/audit-logs?action=…&actor=…&entity=…&limit=100&offset=0`

Returns up to 500 entries:

```json
[ { "id": 1, "org_id": 1, "actor_id": 1, "actor_email": "admin@company-example.com",
    "action": "CREATE_TRUSTED_DOMAIN", "entity": "trusted_domain", "entity_id": "3",
    "prev": {}, "new": { "domain": "maybank2u.com" }, "ip": "127.0.0.1",
    "user_agent": "…", "result": "SUCCESS", "created_at": "…" } ]
```

### `GET /api/audit-logs/actions`

Distinct action names already recorded for the org.

---

## Users

All require `super_admin`.

### `GET /api/users?role=…`

### `POST /api/users`

```json
{ "email": "engineer@company-example.com", "full_name": "Jane", 
  "role": "EMPLOYEE", "password": "at-least-10-chars", "status": "ACTIVE" }
```

Errors: `400` invalid role, `409` email exists.

### `PUT /api/users/{id}`

All fields optional: `full_name`, `role`, `status` (`ACTIVE`/`DISABLED`),
`password` (min 10). Disabling a user revokes all their sessions.

---

## Settings

All require `admin`.

### `GET /api/settings/risk-thresholds`

`{"low": 20, "moderate": 50, "high": 75}` (per org, stored in
`system_settings`).

### `PUT /api/settings/risk-thresholds`

Body `{"low": 30, "moderate": 50, "high": 75}`. Validation: fields must satisfy
`0 ≤ low ≤ 49`, `1 ≤ moderate ≤ 74`, `2 ≤ high ≤ 99`, and
`low < moderate < high` (else `400`).

---

## Email analysis

### `POST /api/email/analyze`

Optional authentication (email-gateway friendly). Body:

```json
{
  "from_header": "Security <noreply@example.com>",
  "reply_to": "hr@company-examle.com",
  "subject": "Your account has been suspended",
  "body": "Verify your password immediately.",
  "links": [ { "text": "example.com", "href": "https://examp1e.com/login" } ],
  "attachments": [ { "filename": "invoice.exe", "mime_type": "application/x-msdownload" } ]
}
```

Response `200`:

```json
{
  "provider_header_from": "…", "sender_address": "…", "sender_domain": "company-examle.com",
  "reply_to_address": "…", "reply_to_domain": "company-examle.com",
  "subject": "…", "impersonates": "company.com", "sender_fold_match": false,
  "keyword_hits": ["suspended", "password", "verify"],
  "display_mismatches": [ { "display_text": "example.com", "url": "https://examp1e.com/login",
                            "hostname": "examp1e.com", "risk_score": 63, "classification": "MALICIOUS", "reasons": […] } ],
  "link_findings": [ /* every link evaluated by the URL analyzer */ ],
  "attachment_risks": ["invoice.exe"],
  "classification": "MALICIOUS",
  "risk_score": 87,
  "reasons": [ … ]
}
```

---

## Threat intelligence feed

### `GET /api/threat-intel`

Admin or super-admin. Status of the keyless live feed:

```json
{
  "enabled": true,
  "feed": "URLhaus (abuse.ch) hostfile — keyless",
  "sync_interval_minutes": 30,
  "max_items_per_sync": 5000,
  "known_threats": 386,
  "last_sync": "2026-09-02T06:00:16+00:00",
  "per_scan_providers_enabled": false
}
```

### `POST /api/threat-intel/sync`

Admin or super-admin. Triggers an immediate sync; downloads the public URLhaus
hostfile and imports fresh hosts into `known_threats` (source
`URLHAUS_FEED`), evicting the oldest feed rows past
`TI_SYNC_MAX_TOTAL`. Writes a `SYNC_THREAT_INTEL` audit entry.

```json
{ "ok": true, "source": "URLHAUS_FEED", "fetched": 383, "added": 3,
  "total_known_threats": 386, "last_sync": "2026-09-02T06:00:16+00:00" }
```

`added` is 0 when the feed has not changed since the last sync. Feed failures
return `{"ok": false, "error": "…"}` with HTTP 200 (the feed is best-effort and
never failure-crashy).

---

## Blocked sites & content policy

A blocked site is a `known_threats` row. Rows **without a category** are always
treated as malware. Rows **with a category** (`GAMBLING`, `ADULT`,
`SOCIAL_MEDIA`, `OTHER`) are only enforced while that category is enabled in the
organisation's content policy, so betting / adult categories can be blocked
org-wide and lifted later from the console.

### `GET /api/blocked-sites`

Admin or super-admin. Lists blocked sites for the org.

```json
[
  { "id": 4, "org_id": 1, "domain": "bet-demo-casino.com",
    "category": "GAMBLING", "note": "", "source": "MANUAL",
    "created_at": "2026-09-02T09:00:00+00:00" }
]
```

### `POST /api/blocked-sites`

Adds a blocked site. Body: `{ "domain": "…", "category": "GAMBLING", "note": "" }`.
`category` is optional; an empty category means "always blocked malware".
Returns `201`; `409` when already blocked; `422` for an invalid domain; `400`
for an unknown category. Writes a `CREATE_BLOCKED_SITE` audit entry.

### `PUT /api/blocked-sites/{id}`

Updates the category/note. `404` if the row does not belong to the org.
Writes `UPDATE_BLOCKED_SITE`.

### `DELETE /api/blocked-sites/{id}`

Unblocks the site. Writes `DELETE_BLOCKED_SITE`.

### `POST /api/blocked-sites/import`

Bulk import as multipart CSV file. Columns `domain[,category[,note]]`, an
optional `domain,category,note` header is ignored. Returns
`{ "added": n, "skipped": n, "errors": [ … ] }`. Writes `IMPORT_BLOCKED_SITES`.

### `GET /api/settings/content-policy`

Returns the org's active blocked categories, e.g. `["GAMBLING","ADULT"]`
(default).

### `PUT /api/settings/content-policy`

Body `{ "categories": ["GAMBLING"] }` (subset of `GAMBLING`, `ADULT`,
`SOCIAL_MEDIA`, `OTHER`). Returns `400` for unknown categories. Writes
`UPDATE_CONTENT_POLICY`. Scans of categorized sites are classified
`MALICIOUS` (score 100) with a policy reason only while their category is in
this list.

---

## Health

### `GET /api/health`

`{"status":"ok","service":"Anti-Phishing URL Protection Platform"}`.

---

## Interactive docs

When `APP_DEBUG=true`, OpenAPI is served at:
- `/api/docs` (Swagger UI)
- `/api/openapi.json`