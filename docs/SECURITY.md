# Security Model

This document describes the threat model, the controls in place, and the
opsec rules for operating PhishGuard.

## Assets being protected

1. **Employees** — from clicking phishing URLs or replying to phishing emails.
2. **The trust model** — the list of approved domains (if an attacker edits the
   list, detection quality collapses).
3. **Integrity data** — audit logs, scan history, user roles.
4. **Secrets** — admin passwords, `.env`, session tokens, TI API keys.

## What we do NOT do

- We never **fetch** or visit analysed URLs. Analysis is purely string-based
  (parse + normalize + match). This makes the analyser immune to SSRF by
  design. The only outbound network calls are optional, and only to a fixed TI
  allow-list.
- We do not use cookies, so **CSRF is structurally impossible** — every call
  carries an explicit bearer token.

## Authentication

- Passwords are hashed with **PBKDF2-HMAC-SHA256**, default 310,000 iterations
  (tunable via `PBKDF2_ROUNDS`).
- Sessions are server-side rows in `sessions`, revocable (logout, or when an
  admin disables a user). Tokens are 256-bit random values.
- Rate limiting on `auth` (default 10/min) slows brute force.
- Failed login attempts are written to the audit log (`AUTH_FAILED`, result
  `FAIL`).

## Authorization (RBAC)

Four roles enforced by dependency guards in `app/security.py`:

| Role               | Key capabilities                                            |
|--------------------|--------------------------------------------------------------|
| `EMPLOYEE`         | analyze URLs, submit reports, read own reports               |
| `SECURITY_ANALYST` | + dashboard, triage / resolve reports                        |
| `ADMIN`            | + trusted domains, audit log, risk thresholds                |
| `SUPER_ADMIN`      | + user lifecycle (create / modify / disable / reset)         |

Every query is scoped by `org_id` and (for reports) `user_id`, so users from
one organisation can never read another organisation’s data within a shared
deployment. Disabling a user revokes all sessions immediately.

## Trusted-domain integrity

- Adding/removing trusted domains is admin-only and **audited** (`prev`/`new`
  JSON snapshots + history endpoint per domain).
- Import is CSV-only with `normalized_domain` deduplication per org.
- Subdomains of a trusted apex are trusted (org-controlled), but a record can
  restrict via `allowed_subdomains` rules.

## Detection-evasion resistance

The matching engine is not fooled by the cheap tricks:

- Unicode homoglyphs via UTS-46 + confusable folding (`еxample.com` Cyrillic Е),
- punycode renderings (`xn--xample-2of.com`),
- mixed-script labels,
- 1–4 character typosquats (`examp1e.com`, `paypa1.com`, `c1tibank.com`),
- brand embedding as subdomain (`example.com.malware.io`) or suffix
  (`securityexample.com`),
- TLD swaps and one-edit TLD confusion,
- credentials-in-URL tricks (`example.com@evil.com`),
- suspicious TLDs and keywords (`secure`, `login`, `verify`, …).

Safety-first classification: an unapproved domain is **never** labelled SAFE;
with any suspicious signal it is SUSPICIOUS even at low scores.

## Data protection

- SQLite file lives at `backend/data/antiphishing.db` (WAL mode). Protect it as
  a system secret: it contains password hashes, sessions and scan history.
- Duration-limited sessions (`TOKEN_TTL_HOURS`, default 7 days).
- Audit logs store IPs and user agents for DFIR.
- All timestamps UTC ISO-8601.

## Transport & browser hardening

Security headers set by a global middleware:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
X-XSS-Protection: 1; mode=block
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

There are **no inline scripts** anywhere in the frontend; every string rendered
from API data passes through `UI.esc()`, so the app has no self-XSS surface.

## Outbound threat-intelligence

Two layers with separate toggles:

- **Keyed per-scan providers** (VirusTotal, Google Safe Browsing, URLhaus JSON).
  Off by default (`ENABLE_EXTERNAL_TI=false`). When enabled:
  - Only provider hostnames from a fixed allow-list are contacted (see
    `app/services/ssrf.py`), always HTTPS, with connection timeouts.
  - Redirects and raw IPs are rejected.
  - Results are cached per scan in `threat_intel_results`.
- **Keyless live feed** (`TI_SYNC_ENABLED=true`, on by default). Downloads the
  public URLhaus hostfile from `urlhaus.abuse.ch` on a schedule. Additions are
  treated as *confirmed malicious* in the local repository (source
  `URLHAUS_FEED`), so they weigh as 100. The bulk download goes through the
  same SSRF allow-list and redirect guard as the keyed providers. It never
  touches user-supplied URLs.

## Content-policy blocks (gambling, adult, social)

Blocked-site rows may carry a category (`GAMBLING`, `ADULT`, `SOCIAL_MEDIA`,
`OTHER`). Uncategorized rows are unconditional malware. Categorized rows are
enforced only while the category is in the org's content policy
(see `GET/PUT /api/settings/content-policy`). A policy block forces
`MALICIOUS` / score 100 during analysis, is rendered as a dedicated "policy
block" banner on the warning page, and is recorded in the audit trail
(`CREATE_BLOCKED_SITE`, `UPDATE_CONTENT_POLICY`, etc.). To prevent bypass,
categorized entries are keyed on the exact registered domain and its
subdomains (no bare-TLD matches).

## Rate limiting

Token-bucket middleware with route grouping:

| Route group | Default limit |
|-------------|---------------|
| `analyze`   | 30 / minute   |
| `auth`      | 10 / minute   |
| default     | 120 / minute  |

## Operating rules (checklist)

1. Generate a **new** `DEFAULT_ADMIN_PASSWORD` in `.env` before first boot;
   change the super-admin password again afterwards.
2. Keep `ENABLE_EXTERNAL_TI=false` unless an API key is configured.
3. Store `DATABASE_PATH` on encrypted storage; back it up with the audit log.
4. Front `/api` and `/app` behind TLS in any non-local deployment (this
   repository does not bundle TLS termination).
5. Run with `APP_DEBUG=false` in production to remove `/api/docs`.
6. Restrict the network so that only the app host can reach `/api/trusted-domains`,
   `/api/users` and `/api/audit-logs` if you expose this internally.
7. When binding `HOST=0.0.0.0`, only expose the port inside a trusted network /
   VPN and allow inbound TCP 8000 only for that scope in Windows Firewall —
   never expose the console or credential-rotation UI to the public internet
   without a reverse proxy + strong auth.
8. The keyless feed imports `known_threats` as trusted malicious data; the feed
   is abuse.ch community-reported. In high-assurance environments, keep
   `TI_SYNC_ENABLED=false` or review imports before treating them as final — the
   audit trail records every `SYNC_THREAT_INTEL` so imports can be reviewed.

## Incident response hooks

- Every mutation and every scan is in the audit log (`/api/audit-logs`,
  filters: action, actor, entity).
- Employees can submit `CONFIRMED_THREAT` candidate URLs to the triage queue.
- Deleting a compromised trusted domain is immediate and audited.