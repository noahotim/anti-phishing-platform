# Architecture

PhishGuard is a classic API-first application: a FastAPI backend owns all logic
and data, and a static, dependency-free frontend consumes the JSON API. There is
no build step and no external CDN — everything is served by the backend, which
keeps the CSP strict (`default-src 'self'`).

## High-level diagram

```
                      ┌──────────────────────────────────────────────┐
                      │                 FastAPI app                  │
                      │                                              │
  HTML/CSS/JS ──────► │  static mounts (/, /app, /login, /assets,    │
  (frontend)          │                /scripts)                     │
                      │                                              │
  Employee / Analyst  │  routers            middleware               │
  / Admin browser ──► │  · auth            · security headers (CSP)  │
                      │  · analyze         · rate limiting (bucket)  │
                      │  · reports         · validation/error handl  │
                      │  · dashboard                                  │
                      │  · trusted-domains                           │
                      │  · audit, users, settings, email             │
                      └──────────────┬───────────────────────────────┘
                                     │ services
                      ┌──────────────▼───────────────────────────────┐
                      │  UrlAnalyzer ──► SimilarityEngine            │
                      │     parse ─ normalize ─ trust-lookup ─       │
                      │     confusable ─ score ─ classify ─ notify   │
                      │  EmailAnalyzer                                │
                      └──────────────┬───────────────────────────────┘
                                     │ thread-local connection (WAL)
                      ┌──────────────▼───────────────────────────────┐
                      │            SQLite (data/antiphishing.db)      │
                      └──────────────────────────────────────────────┘
```

External threat-intel providers (VirusTotal / Google Safe Browsing / URLhaus)
are optional and **off by default**; when enabled, outbound calls go through the
SSRF guard described below.

## Detection pipeline (`app/services/analyzer.py`)

For a submitted URL, `UrlAnalyzer.analyze()` runs these stages:

1. **Parse** (`url_parser.py`) — split into scheme, credentials, host, port,
   path, query. The parser is deliberately strict and never makes network
   calls; if anything is ambiguous it is kept as a warning, not guessed.
2. **Normalize** (`normalization.py`) — UTS-46 mapping via the `idna` package
   (not the stdlib codec, which rejects modern punycode), Unicode↔ASCII forms,
   plus a `fold_for_similarity*` helper that maps confusable characters to a
   canonical ASCII key.
3. **Trust lookup** — is the hostname an exact approved domain, an approved
   subdomain, or controlled by the org? Subdomains of a trusted apex are trusted
   unless the trusted record declares `allowed_subdomains` restrictions.
   A separate local list of `known_threats` is consulted by the TI layer.
4. **Similarity analysis** (`similarity.py`, `homoglyph.py`) — for every trusted
   domain compute a `DomainFinding` containing:
   - Unicode fold-match (the classic `еxample.com` Cyrillic-E trap),
   - Damerau–Levenshtein edit distance (typosquatting: `examp1e`, `exampe`),
   - TLD comparison and one-character TLD confusions (`example.com` → `.cm`),
   - misleading subdomains (`example.com.security-malware.io`),
   - brand-embedded suffixes (`securityexample.com`),
   - brand prefixes (`example-secure.com`),
   - suspicious TLDs and suspicious keywords (`login`, `verify`, `secure` …),
   - punycode / mixed-script indicators.
   The best finding is the one carrying the *strongest deception signal*
   (fold-match / embedding beats a merely-nearest edit distance).
5. **Risk scoring** (`risk_scorer.py`) — weighted signal sum capped at 100.
   Rough weights (see source for the exact table): untrusted baseline 8,
   edit distance 46/30/20/12 (1/2/3/4 ops), confusable exact match 55,
   TI-confirmed malicious 55, brand embedding 48, userinfo-in-URL 26,
   IP-as-host 26, suspicious TLD 15, mixed script 14, etc.
6. **Classification** — mappings are order-sensitive:
   - exact approved (or TI-benign) and score ≤ low ⇒ `SAFE`,
   - score > high ⇒ `MALICIOUS` (risk level HIGH or CRITICAL when ≥ 76),
   - score > moderate ⇒ `MALICIOUS`,
   - score > low ⇒ `SUSPICIOUS`,
   - score > 0 with any signal ⇒ `SUSPICIOUS` (safety-first),
   - otherwise `UNKNOWN`. An unapproved domain is never `SAFE`.
7. **Persistence + audit** — the scan, matched-domain, signals, reasons and
   threat-intel results are stored, and an `SCAN_URL` audit entry is written.
8. The result is serialized with `to_dict()` (see [API.md](API.md) for the shape).

## Email analysis (`app/services/email_analyzer.py`)

`EmailAnalyzer` is API-ready but the frontend exposes a compact form. It:

- parses the `From` header and `Reply-To` with the stdlib email parser,
- runs similarity checks between the sender domain and trusted domains
  (substitution / transposition / homoglyph detection, e.g.
  `accounts@cornpany.com` impersonating `company.com`),
- evaluates each link with the URL analyzer and flags
  display-text-vs-`href` mismatches,
- scans the subject/body against a configurable keyword list
  (`verify`, `invoice`, `urgent`, …),
- flags risky attachments by filename extension / MIME type.

## Threat intelligence (`app/services/threat_intel.py`, `ti_sync.py`, `ssrf.py`)

- **Internal repository:** confirmed threats live in `known_threats` and are
  checked for every scan.
- **Keyless live feed (`ti_sync.py`):** the public abuse.ch URLhaus hostfile is
  downloaded at startup and then every `TI_SYNC_INTERVAL_MIN` minutes by a
  background task in `app/main.py`'s lifespan, then imported into
  `known_threats` (source `URLHAUS_FEED`). Manual rows are never evicted; when
  the total exceeds `TI_SYNC_MAX_TOTAL`, the oldest feed rows are deleted. It is
  independent of the keyed per-scan providers and works with no API keys.
- **External providers:** optional plug-ins for VirusTotal, Google Safe
  Browsing, and URLhaus (keyed).
- **SSRF guard:** the SSRF module refuses to contact anything except a fixed
  allow-list of TI hosts/domains, always over HTTPS, with configurable
  timeouts, and never follows redirects to other hosts. All outbound TI calls
  (per-scan *and* the bulk feed download) run only against allow-listed hosts —
  never user-supplied URLs.
- **On-demand sync:** admins can trigger `POST /api/threat-intel/sync` (logged
  as `SYNC_THREAT_INTEL` in the audit trail).

## Content policy (`app/content_policy.py`, `routers/blocked_sites.py`)

Organisations can block whole *categories* of websites — gambling/betting,
adult content, social media — in addition to confirmed malware:

- `known_threats` gains a `category` column. Rows **without** a category are
  always treated as malware. Rows **with** a category are only enforced while
  that category is active in the org's content policy.
- The active categories are stored as JSON in `system_settings`
  (key `content_policy`), default `["GAMBLING", "ADULT"]`, and edited via
  `GET/PUT /api/settings/content-policy`.
- `routers/blocked_sites.py` manages the list (CRUD + CSV import).
- During analysis (`services/analyzer.py`), a categorized hit that is active in
  the policy forces the verdict to `MALICIOUS` / score 100 with reason
  "Blocked by organization policy", and the response carries
  `content_blocked: true` and `blocked_category`. The warning page renders this
  as a dedicated **policy block** banner so employees see why the site is
  stopped.

## Concurrency & data layer

SQLite runs in WAL mode with `foreign_keys=ON` and a 30 s busy timeout.
`database.py` exposes thread-local connections and transactional helpers
(`fetchone`/`fetchall`/`execute`) so routers never manage raw connections.
All timestamps are UTC ISO-8601. Every table has explicit indexes on its query
paths (see [DATABASE.md](DATABASE.md)).

## Frontend

Plain HTML/CSS/JS, no frameworks:
- `frontend/js/api.js` — fetch wrapper with bearer-token handling;
- `frontend/js/common.js` — shared topbar, toasts, escaping, formatting;
- `frontend/js/index.js` — URL checker + (role-gated) email analyzer;
- `frontend/js/admin.js` — tabbed console: dashboard, reports, trusted
  domains, blocked sites + content policy, audit, users, thresholds;
- `frontend/js/warning.js` — dangerous-link interstitial that can be opened
  with `?url=…&scan_id=…` (authenticated) **or** with
  `?blocked=1&url=…&label=…&reason=…` (anonymous — used by the browser guard,
  so a user who isn't signed in still gets the block screen).

`api.js` stores the session token in `localStorage` and redirects to the login
page on 401. Every user-controlled string passes through `UI.esc()` before
insertion, and the platform CSP blocks inline scripts — so there is no XSS
surface from the app itself.

## Browser guard (`extension/`)

An MV3 Chrome/Edge extension that blocks automatically, with no link-pasting:

- At startup and every 30 minutes it pulls `GET /api/guard/rules` and installs
  `declarativeNetRequest` redirect rules for manual/seed-blocked domains (filtered
  to the active content policy), so known-bad pages can't even begin loading.
- Every top-level `http(s)` navigation is submitted to `POST /api/analyze/precheck`
  (anonymous, `persist=False`, no audit). Blocked verdicts redirect the tab to
  the platform's `warning.html` interstitial. A 10-minute in-memory host cache
  and per-URL in-flight dedupe keep server traffic near one call per new domain.
- It never blocks the platform itself, never blocks sub-frames, can be paused
  15 minutes from the popup, and fails open (browsing continues) while the
  server is unreachable.

Both guard endpoints are anonymous by design — they expose only the *blocked
domain* set and per-URL verdicts, never user data, and are intended for the
trusted internal fleet.

## Data flows and role boundaries

| Route group            | Minimum role         | Notes                                        |
|------------------------|----------------------|----------------------------------------------|
| `POST /api/analyze/url`| anonymous            | anonymous scans org 1; logged-in → own org   |
| `POST /api/analyze/precheck`| anonymous        | side-effect-free verdict, no scan/audit      |
| `GET /api/guard/rules` | anonymous            | blocked-domain feed for the browser guard    |
| `GET /api/dashboard/*` | analyst              |                                              |
| `POST /api/reports`    | any authenticated    | employees see/manage only their own          |
| `PUT /api/reports/*`   | analyst              | triage workflow                              |
| `/api/trusted-domains` | admin                | enforcement happens inside the engine        |
| `/api/audit-logs`      | admin                | searchable                                   |
| `/api/settings/*`      | admin                | per-org risk thresholds                      |
| `/api/users/*`         | super admin          | role + status + password                     |