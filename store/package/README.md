# PhishGuard — Browser Guard extension

Automatically guards every site your users open: navigations are checked
against your PhishGuard server, and blocked pages (phishing / malware /
gambling / adult / social) are redirected to the PhishGuard warning
interstitial before the user ever sees them. **No manual link-pasting needed.**

Works on Chrome / Edge / Chromium (Manifest V3).

## How it blocks

| Layer | Mechanism | Catches | Latency |
| --- | --- | --- | --- |
| 1. Declarative Net Request | Redirect rules installed from `GET /api/guard/rules` (manual + seed blocks) | Known blocked domains, incl. exact gambling/adult/social | Instant (network layer) |
| 2. Async precheck | `POST /api/analyze/precheck` on every top-level navigation | Threat feeds, typosquats, homoglyphs, fuzzy matches — the long tail | ~1 request per navigation (10-min local cache) |

Unknown sites are *never fetched* by the platform — only the URL is analyzed
against the knowledge base. If the server is unreachable the guard fails open
(browsing continues) and the popup shows the problem.

## Install

### Option A — manual (test / small fleet)

1. Open `chrome://extensions` (Chromium) or `edge://extensions`.
2. Enable **Developer mode** (top-right).
3. Click **Load unpacked** and select this `extension/` folder.
4. Click the PhishGuard icon → **Options** → set your server URL
   (default `http://192.168.100.43:8000`) → **Save** → **Refresh blocked domains**.

### Option B — enterprise policy (recommended for real fleets)

1. ZIP the `extension/` contents and host it on an internal HTTPS share.
2. Push an update URL policy so Chrome auto-installs and keeps it updated:
   - Chromium: `ExtensionSettings` (`extension_settings` policy) with
     `update_url`, `installation_mode: force_installed`, and the
     `externally_managed` PRD.
   - Edge: Microsoft Edge management service / `ExtensionInstallationList`.
3. Set `update_url` to your internal CRX updater (e.g. your WSUS/GPO host).

> The extension requests `<all_urls>` and an API host permission. This is an
> internal defensive tool — approve it only on machines you control.

## Configuration (Options page)

- **Server URL** — your PhishGuard instance (e.g. `http://192.168.100.43:8000`).
- **Also hold SUSPICIOUS** — off by default; only `MALICIOUS` pages are
  blocked. Enable to also intercept `SUSPICIOUS` verdicts.
- **Test connection** — verifies the server with a known-bad sample URL.
- **Refresh blocked domains** — re-pulls `/api/guard/rules` (also auto-refreshes
  every 30 minutes and on browser start).

## Popup

Shows the server, number of protected domains, the latest block, a **Pause for
15 minutes** control (useful while hunting false positives), **Check this page**
(instant verdict for the current tab), and a link to options.

## Endpoints the extension uses (all anonymous)

- `GET  /api/guard/rules` — list of currently blocked domains + active policy
  categories. Only manual/seed rows; never the whole threat feed.
- `POST /api/analyze/precheck` — full detector, no DB writes and no audit row,
  so per-navigation checks stay cheap.

## Notes & limits

- Rate limiting: precheck shares the `/api/analyze` bucket (`30/minute`
  default per IP). Per-navigation caching keeps real traffic near one request
  per new host; raise `ANALYZE_RATE_LIMIT` in the server `.env` if needed.
- Maximum dynamic DNR rules used: `4900`; the guard feed is far below that.
- Firefox MV3 support for `declarativeNetRequest` redirects is partial — Chrome
  and Edge are fully supported. A Firefox port can reuse `background.js` with
  webRequest-based fallback.