# PhishGuard — Anti-Phishing URL Protection Platform

Internal platform that helps employees and security analysts detect deceptive
(phishing / typosquatting / homoglyph) URLs before anyone clicks them.

- **URL checker** — paste any link, get an instant verdict with an explanation.
- **Configurable risk scoring** — score 0–100, verdicts SAFE / SUSPICIOUS /
  MALICIOUS / UNKNOWN, thresholds editable per organisation.
- **Detection engine** — registered-domain extraction, public-suffix rules,
  IDN/UTS-46 normalisation, Unicode homoglyph folding, mixed-script detection,
  edit-distance typosquatting, TLD confusion, brand/subdomain embedding, and a
  pluggable threat-intelligence layer.
- **Admin console** — dashboard, phishing report triage, trusted-domain
  management (with CSV import/export), blocked-sites management, audit log,
  user & role administration, risk-threshold settings.
- **Content policy** — organisations can block whole categories of sites
  (gambling/betting, adult content, social media) from the console. Categorised
  blocked sites are stopped with a clear "policy block" warning whenever opening
  them, and a category can be enabled or lifted at any time from Settings.
- **Email analysis service** — sender impersonation, display-text-vs-href link
  mismatches, risky keywords and attachments (API ready for gateway integration).
- **Live threat feed** — a keyless background sync pulls fresh malicious hosts
  from the abuse.ch URLhaus hostfile into `known_threats` (configurable interval,
  per-sync and total caps, admin-triggerable "sync now" from the console) so
  every scan is checked against real, recently-active phishing infrastructure.
- **Browser guard extension** — an MV3 Chrome/Edge extension that watches every
  site users open, checks it against the server (`/api/analyze/precheck`) and
  instantly blocks known phishing / malware / gambling / adult / social pages
  with the warning interstitial — no manual link-pasting required. See
  [`extension/README.md`](../extension/README.md).
- Hardened by design: PBKDF2-HMAC-SHA256 password hashing, revocable bearer
  sessions, role-based access control, per-route rate limiting, SSRF-safe
  analysis (URLs are never fetched), a full audit trail, and strict CSP headers.

---

## Stack

| Layer      | Technology                                              |
|------------|---------------------------------------------------------|
| Backend    | Python 3.13, FastAPI, uvicorn, pydantic                 |
| Storage    | SQLite (stdlib, WAL) — zero configuration              |
| Frontend   | Static HTML/CSS/JS served by FastAPI (no build step)   |
| Detection  | Custom engine + `idna` (UTS-46) for IDN handling       |
| Tests      | pytest + FastAPI TestClient                            |

## Repository layout

```
antiphishing-platform/
├── backend/
│   ├── app/
│   │   ├── main.py            # app assembly, security headers, static mounts
│   │   ├── config.py          # environment-driven settings
│   │   ├── database.py        # SQLite schema + helpers
│   │   ├── security.py        # sessions, RBAC dependencies
│   │   ├── hashing.py         # PBKDF2-HMAC-SHA256
│   │   ├── rate_limiter.py    # token-bucket middleware
│   │   ├── audit.py           # audit-log writer
│   │   ├── seed.py            # initial organisation / admin / demo data
│   │   │   ├── routers/           # REST API (auth, analyze, reports, dashboard,
│   │   │   │   #   trusted-domains, blocked-sites, guard, audit, users, settings,
│   │   │   │   #   email, threat-intel)
│   │   │   └── services/          # url_parser, normalization, homoglyph,
│   │   │       #   similarity, public_suffix, risk_scorer,
│   │   │       #   analyzer, email_analyzer, threat_intel, ti_sync, ssrf
│   │   ├── content_policy.py  # blocked-site categories (gambling, adult, …)
│   ├── tests/                 # pytest suite (134 tests)
│   ├── requirements.txt
│   └── .env.example
├── extension/                 # MV3 browser guard (Chrome/Edge)
├── frontend/                  # static UI (index, login, admin, warning)
└── docs/                      # this documentation set
```

## Quick start (development)

Requirements: Python 3.12+ on Windows/macOS/Linux.

```powershell
# 1. virtualenv and dependencies
cd backend
python -m venv ..\.venv
..\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. configuration
Copy-Item .env.example .env          # edit secrets, especially DEFAULT_ADMIN_PASSWORD

# 3. run the server (init_db + seed run automatically on startup)
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
# open http://127.0.0.1:8000  (redirects to /app/index.html)
```

On Linux/macOS use `.venv/bin/python` and `cp .env.example .env`. To run so the
service is reachable from the LAN (as `.env` ships with `HOST=0.0.0.0`):

```powershell
../.venv/Scripts/python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Allow inbound TCP 8000 through Windows Firewall for the LAN interface (or expose
it publicly only inside a restricted network / VPN — see [SECURITY.md](SECURITY.md)).

### First sign-in

The starter organisation and admin are created by `seed.py` on first boot:

- **email:** `admin@company-example.com`
- **password:** whatever you set in `.env` → `DEFAULT_ADMIN_PASSWORD`
  (the committed `.env.example` only ever contains `ChangeMe_123!` — change it
  before going anywhere near production, and change it again after first login).

Employee accounts can be created from the admin console *(Users tab)* — only a
`SUPER_ADMIN` can create or modify users.

## Running the test suite

```powershell
..\.venv\Scripts\python.exe -m pytest -q
```

On Windows consoles that cannot print Cyrillic test fixtures, set
`$env:PYTHONIOENCODING='utf-8'` first. Tests use a throwaway database in a
temporary directory and never touch your real `data/` database.

## Environment variables

See [`.env.example`](backend/.env.example) for the authoritative list. Key items:

| Variable | Purpose | Default |
|----------|---------|---------|
| `APP_ENV` / `APP_DEBUG` | run mode, FastAPI `/api/docs` toggle | development / false |
| `DATABASE_PATH` | SQLite file (relative to `backend/`) | `data/antiphishing.db` |
| `SEED_ON_STARTUP` | seed org + admin + demo data | true |
| `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` | bootstrap admin | `admin@company-example.com` / empty |
| `TOKEN_TTL_HOURS` | session lifetime | 168 (7 days) |
| `PBKDF2_ROUNDS` | password-hash cost | 310000 |
| `RATE_LIMIT_ENABLED`, `ANALYZE_RATE_LIMIT`, `AUTH_RATE_LIMIT`, `GENERIC_RATE_LIMIT` | token-bucket limits | on; 30/m; 10/m; 120/m |
| `ENABLE_EXTERNAL_TI` | keyed external providers (VT / GSB / URLhaus JSON) | **false** (off by default) |
| `TI_SYNC_ENABLED` | keyless live URLhaus hostfile sync | **true** |
| `TI_SYNC_INTERVAL_MIN` / `TI_SYNC_MAX_ITEMS` / `TI_SYNC_MAX_TOTAL` | feed cadence and caps | 30 / 5000 / 100000 |
| `STATIC_DIR` | frontend directory | `../frontend` |
| `HOST` / `PORT` | uvicorn bind address | 0.0.0.0 / 8000 |

External threat intelligence comes in two flavours:

1. **Keyed per-scan providers** (VirusTotal, Google Safe Browsing, the URLhaus
   JSON API) — disabled unless you set `ENABLE_EXTERNAL_TI=true` **and** provide
   at least one API key. The SSRF guard only allows calls to a fixed allow-list
   of TI hosts.
2. **Keyless live feed** (`TI_SYNC_ENABLED=true`) — at startup and then every
   `TI_SYNC_INTERVAL_MIN` minutes the app downloads the public URLhaus hostfile
   (`https://urlhaus.abuse.ch/downloads/hostfile/`) and imports hosts into
   `known_threats` with source `URLHAUS_FEED`. Oldest feed rows are evicted when
   the total exceeds `TI_SYNC_MAX_TOTAL`; manually added rows are never evicted.
   Admins can also trigger a sync from *Admin → Overview → Live threat feed → Sync
   now*, or `POST /api/threat-intel/sync`.

## Pages

- `/app/index.html` — employee URL checker (+ optional email analyzer for
  logged-in analysts/admins)
- `/app/login.html` — sign-in
- `/app/admin.html` — console (role-gated tabs)
- `/app/warning.html?url=…&scan_id=…` — dangerous-link interstitial
- `/app/warning.html?blocked=1&url=…&label=…&reason=…` — same interstitial
  rendered from URL parameters (used by the browser guard for anonymous users)

## Browser guard extension

The `extension/` folder is a Manifest V3 extension that protects users without
asking them to paste links:

- **Network layer** — installs `declarativeNetRequest` redirect rules from
  `GET /api/guard/rules` (manual + seed blocked domains, filtered to the active
  content policy) so known-bad pages never load at all.
- **Per-navigation check** — every top-level `http(s)` navigation is submitted
  to `POST /api/analyze/precheck` (unauthenticated, side-effect-free — no scan
  rows, no audit entries) and blocked pages are redirected to the warning
  interstitial. A 10-minute in-memory cache keeps requests near one per new
  domain.

To deploy: open `chrome://extensions` / `edge://extensions` → Developer mode →
**Load unpacked** → pick `extension/`, then set the server URL in the extension
options. Full install/deployment guidance is in
[`extension/README.md`](../extension/README.md).

## Documentation set

- [ARCHITECTURE.md](ARCHITECTURE.md) — engine pipeline, components, diagram
- [API.md](API.md) — every endpoint, payload, and example
- [SECURITY.md](SECURITY.md) — threat model and hardening
- [DATABASE.md](DATABASE.md) — schema and indexes
- [TESTING.md](TESTING.md) — running, contributing, and debugging tests

## Roles

| Role               | Can do                                                                 |
|--------------------|------------------------------------------------------------------------|
| `EMPLOYEE`         | Check URLs, report phishing, view own reports                          |
| `SECURITY_ANALYST` | Everything above + dashboard, report triage                            |
| `ADMIN`            | Analyst powers + trusted domains, audit log, settings                  |
| `SUPER_ADMIN`      | Admin powers + user lifecycle management                               |