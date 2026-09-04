# PhishGuard — Anti-phishing Platform

**Author:** Noah Otim ([@noahotim](https://github.com/noahotim) — otim.no25@gmail.com)

A self-hosted phishing intelligence platform with an automatic **browser
guard**. It scans links and every site you open, blocks phishing, malware,
gambling, adult and social-media pages behind a warning interstitial, and
gives an admin console for managing the threat list, policies and audits.

## Components

| Path                | What it is                                             |
| ------------------- | ------------------------------------------------------ |
| `backend/`          | FastAPI service (scan/analyze, policy blocks, guard endpoints, admin API, SQLite DB) |
| `frontend/`         | Web app: login, console, and the warning interstitial  |
| `extension/`        | Chrome / Edge (MV3) browser guard                       |
| `extension-firefox/`| Firefox (MV2) browser guard                             |
| `dist/`             | Packaged installers (signed/unsigned `.xpi`, etc.)      |
| `docs/`             | README, API, architecture, database, security, testing + operations manual |

## Quick start (backend)

```powershell
cd backend
$env:PYTHONIOENCODING="utf-8"
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open the app: `http://192.168.100.43:8000/app/index.html`

Tests: `cd backend; ..\.venv\Scripts\python.exe -m pytest -q` (134 passing)

## Browser guard

The extension calls two anonymous endpoints:

- `POST /api/analyze/precheck` — verdict for any URL (compact, no audit row)
- `GET /api/guard/rules` — the current blocked-domain list

Blocked sites bounce to an extension-hosted red warning page. Since v1.1.0 a
**"I understand the risks, continue anyway"** button lets the user proceed to
a flagged site for 30 minutes.

See `extension-firefox/README.md` (Firefox) and `extension/README.md`
(Chrome/Edge) for install details.

## Firefox permanent install

Firefox Release only keeps **signed** add-ons. Options:

1. **AMO signing** — upload `dist\phishguard-firefox.xpi` at
   addons.mozilla.org/developers (self-distribution → automatic signing), then
   install the signed file. Survives restarts on Release Firefox.
2. **Developer Edition / Nightly** — allows unsigned add-ons via
   `xpinstall.signatures.required=false`.

## Documentation

- `docs/README.md` — overview
- `docs/API.md` — REST endpoints
- `docs/ARCHITECTURE.md` — data flow & design
- `docs/DATABASE.md` — schema
- `docs/SECURITY.md` — auth & security model
- `docs/TESTING.md` — test suite
- `docs/System_Operations_Manual.html/.pdf` — full ops manual
