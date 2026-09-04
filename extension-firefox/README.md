# PhishGuard — Firefox build

Firefox uses the WebExtensions event-page model (MV2), so this build ships
next to the Chrome MV3 one. The async per-navigation precheck does all the
blocking here — Firefox doesn't expose Chrome-style `declarativeNetRequest`
dynamic rules, but `background.js` guards for that and works in both.

Since v1.1.0 the warning interstitial is **extension-hosted**
(`warning.html`/`warning.js`) rather than the server page. Blocked sites
bounce to it, and **"I understand the risks, continue anyway"** lets the user
proceed to the site for 3 minutes (host bypass; the background skips that
host and, on Chrome, drops its DNR redirect rule). The server warning page is
still used by the authenticated web-console flows, where only admins/analysts
can override.

## Load it

1. Open Firefox → go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on…**
3. Pick **`extension-firefox\manifest.json`** (this folder)
4. Open **Options** (right-click the PhishGuard toolbar icon) → set the server
   URL to `http://192.168.100.43:8000` → **Refresh blocked domains**
5. Test: open `bet-demo-casino.com` → it must bounce to the PhishGuard warning.

## Important: temporary vs permanent

Standard **Firefox Release** (which you're on) loads unsigned add-ons **only**
via *Load Temporary Add-on* — it works immediately, but Firefox forgets it
after you close the browser. Mozilla blocks the old `xpinstall.signatures.required
=false` bypass on recent Release builds (it only works on **ESR**, **Developer
Edition**, and **Nightly**).

So for a setup that survives restarts, pick one of:

- **Easy, real** — create a free account at addons.mozilla.org, submit this
  build for signing (it's an internal tool; AMO signs quickly), then install
  the signed `.xpi` normally — no bypass needed.
- **Dev/Nightly channel** — run Firefox Developer Edition or Nightly, set
  `xpinstall.signatures.required=false` in `about:config`, then drop the XPI
  into `<profile>\extensions\`.
- **Enterprise policy** (when rolling out to the fleet) — Firefox policies via
  Windows registry can force-install signed add-ons; requires the signed build.

Until you choose one, just **re-load it** (steps above) each time you start
the browser — it takes ~15 seconds. `background.js` is identical to the Chrome
build, so behaviour is the same: instant known-domain blocks, per-navigation
prechecks, fail-open when the server is down, 15-minute pause from the popup.