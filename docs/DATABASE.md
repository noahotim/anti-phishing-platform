# Database

SQLite, WAL journal mode, foreign-key enforcement and a 30-second busy timeout.
The schema is applied idempotently at startup (`database.init_db`) and can be
lifted to PostgreSQL later without redesign — all timestamps are UTC ISO-8601
strings and all JSON blobs are plain text columns.

Default file: `backend/data/antiphishing.db` (override with `DATABASE_PATH`).

```
organizations
──────────────────────────────────────────────
 id, name, slug (unique), created_at

users
──────────────────────────────────────────────
 id, org_id → organizations, email (unique),
 full_name, password_hash, role, status,
 created_at, last_login_at
 ── role CHECK: EMPLOYEE | SECURITY_ANALYST | ADMIN | SUPER_ADMIN
 ── status CHECK: ACTIVE | DISABLED
 idx_users_org, idx_users_email

sessions                                 (revocable bearer tokens)
──────────────────────────────────────────────
 id (PK, the token), user_id → users,
 expires_at, created_at, ip, user_agent
 idx_sessions_user

trusted_domains                            (the trust model)
──────────────────────────────────────────────
 id, org_id → organizations, domain, normalized_domain,
 category, is_critical, allowed_subdomains, notes,
 added_by → users, created_at, updated_at
 UNIQUE(org_id, normalized_domain)
 idx_trusted_org

url_scans
──────────────────────────────────────────────
 id, org_id → organizations, user_id → users (nullable:
 anonymous scans), url, hostname, registered_domain,
 punycode_domain, classification, risk_score,
 matched_domain, signals (JSON), reasons (JSON),
 details (JSON), source, created_at
 idx_scans_org_time, idx_scans_class,
 idx_scans_regdom, idx_scans_user

threat_reports
──────────────────────────────────────────────
 id, org_id, user_id → users, url, analysis (JSON),
 comment, status, reviewed_by → users, reviewed_at,
 created_at
 ── status CHECK: NEW | INVESTIGATING |
                  CONFIRMED_THREAT | FALSE_POSITIVE | RESOLVED
 idx_reports_org_time, idx_reports_status, idx_reports_user

threat_intel_results                       (per-scan TI answers)
──────────────────────────────────────────────
 id, url_scan_id → url_scans (nullable), provider,
 verdict, score, payload (JSON), created_at
 idx_ti_scan

known_threats                              (local TI repository)
──────────────────────────────────────────────
 id, org_id → organizations, domain, note, source,
 category, created_at
 UNIQUE(org_id, domain)
 ── category: "" (always malware) or a content-policy
    category (GAMBLING/ADULT/SOCIAL_MEDIA/OTHER), enforced
    only while that category is active in the org policy
    (see system_settings key `content_policy`)

audit_logs
──────────────────────────────────────────────
 id, org_id, actor_id → users, actor_email, action,
 entity, entity_id, prev (JSON), new (JSON),
 ip, user_agent, result, created_at
 idx_audit_org_time, idx_audit_actor, idx_audit_action

system_settings                            (per-org key/value)
──────────────────────────────────────────────
 id, org_id, key, value (JSON), updated_by → users,
 updated_at
 UNIQUE(org_id, key)                         e.g. key='risk_thresholds'
```

## Notes

- `PK` on `sessions.id` is the raw bearer token (hashed-at-rest optional for
  SQLite; if you need token-at-rest protection, store `SHA-256(token)` instead
  and match on the digest).
- `url_scans.signals / reasons / details` and `threat_reports.analysis` are
  JSON encoded with the stdlib and decoded by the API before serialisation.
- Every write path that matters to compliance (login/logout, auth failures,
  user CRUD, domain CRUD, report triage, threshold changes) goes through
  `audit()` and lands in `audit_logs`.
- WAL mode: you normally keep the three files `antiphishing.db`,
  `-wal`, and `-shm` together when copying a live database.