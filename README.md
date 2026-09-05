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
a flagged site for 3 minutes (3-min host bypass, DNR rule removed on Chrome).

### Browser support

| Browser | Package | Install | Persists after restart |
| ------- | ------- | ------- | ---------------------- |
| **Chrome, Edge, Brave, Opera, Vivaldi** (all Chromium MV3) | `phishguard-chrome.zip` / `extension/` folder | `chrome://extensions` → Developer mode → **Load unpacked** → pick `extension/` (or unzip `phishguard-chrome.zip`); for fleet, publish to Chrome Web Store then force-install via policy | Yes |
| **Firefox Release** | `phishguard-firefox-signed.xpi` (AMO-signed, v1.1.0) | `about:addons` → gear → **Install Add-on From File** → pick the signed `.xpi` | Yes (signed) |
| **Firefox Dev Edition / Nightly / ESR** | `phishguard-firefox.xpi` (unsigned) | `about:debugging` → **Load Temporary Add-on** *or* `about:addons` → Install From File with `xpinstall.signatures.required=false` | Temporary via `about:debugging`; permanent via Install From File on Dev/Nightly/ESR |
| **Safari** | Not packaged (requires Xcode conversion) | Use Firefox/Chrome build or manual URL check at `http://SERVER/app/index.html` | — |

All builds share the same `background.js`/`warning.html` logic (Firefox uses `browser.*`, Chromium uses `chrome.*` via `NS` shim) — instant known-domain blocks + per-navigation precheck, fail-open if the server is unreachable.

See `extension-firefox/README.md` (Firefox) and `extension/README.md`
(Chrome/Edge) for detailed steps. Download ready-to-install files from the GitHub Release **v1.1.4**: `phishguard-firefox-signed.xpi` and `phishguard-chrome.zip` at https://github.com/noahotim/anti-phishing-platform/releases/tag/v1.1.4

### Server URL for other PCs

- **Inside your LAN:** `http://192.168.100.43:8000`
- **Outside your LAN (Noah URL):** `https://dressing-duck-dose-controllers.trycloudflare.com` (public Cloudflare Tunnel — quick tunnel, host changes on restart; for a stable host create a named tunnel)

Noah URL is the default in v1.1.1+ (outside PCs work automatically after install). Set manually in the extension's **Options** → **Save** → **Refresh blocked domains** if needed.

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
