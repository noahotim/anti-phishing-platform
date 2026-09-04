/* PhishGuard browser guard — background service worker.
 *
 * Two-layer blocking:
 *  1. declarativeNetRequest redirect rules for known blocked domains
 *     (manual + seed), refreshed from the server. Instant, network-layer.
 *  2. webNavigation.onBeforeNavigate precheck of every top-level navigation
 *     against the server's /api/analyze/precheck endpoint. Catches the long
 *     tail (threat feeds, typosquats, fuzzy matches, homoglyphs).
 *
 * Unknown threats are resolved with the caller's consent via the server.
 * If the server is unreachable the guard fails OPEN (normal browsing) and
 * the problem is reported on the popup.
 */
"use strict";

// Firefox exposes the promise-based API under `browser`; Chrome (MV3) uses
// `chrome`. Pick whichever exists.
const NS = (typeof browser !== "undefined" && browser) ? browser : chrome;

const DEFAULT_SERVER = "https://fda-wishlist-finds-protection.trycloudflare.com";
const WARNING_PAGE = "warning.html";
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX = 3000;
const RULE_REFRESH_MIN = 30;
const MAX_DNR_RULES = 4900;
const BYPASS_MS = 30 * 60 * 1000;

let cfg = { server: DEFAULT_SERVER, blockSuspicious: false, pauseUntil: 0 };
let threatHosts = [];          // [{host, label, category}]
const verdictCache = new Map(); // host -> verdict
const inFlight = new Map();     // url -> Promise
const bypassHosts = new Map();  // host -> expiry ms (user chose "continue anyway")
const dnrIdByHost = {};         // host -> dynamic rule id (Chrome only)

NS.runtime.onInstalled.addListener(() => { refreshRules(); scheduleRefresh(); });
NS.runtime.onStartup.addListener(() => { refreshRules(); scheduleRefresh(); });
NS.alarms.onAlarm.addListener((a) => { if (a.name === "refreshRules") refreshRules(); });
NS.storage.onChanged.addListener((changes, area) => {
  if (area !== "sync" && area !== "local") return;
  loadCfg().then(() => refreshRules());
});

loadCfg().then(() => refreshRules());

function base() {
  try { return new URL(cfg.server).origin; } catch (e) { return ""; }
}

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------
function loadCfg() {
  // storage.local so it works without a Firefox Sync account.
  return NS.storage.local.get(null).then((raw) => {
    const server = (raw.server || DEFAULT_SERVER).replace(/\/+$/, "");
    cfg = {
      server,
      blockSuspicious: !!raw.blockSuspicious,
      pauseUntil: Number(raw.pauseUntil || 0),
    };
  });
}

function isPaused() {
  return cfg.pauseUntil > Date.now();
}

function scheduleRefresh() {
  NS.alarms.create("refreshRules", { periodInMinutes: RULE_REFRESH_MIN });
}

// --------------------------------------------------------------------------
// Known-threat rules (guard/rules -> DNR redirects + local cache)
// --------------------------------------------------------------------------
async function refreshRules() {
  try {
    const res = await fetchJSON(cfg.server + "/api/guard/rules");
    const rules = Array.isArray(res.rules) ? res.rules : [];
    threatHosts = rules
      .filter((r) => r && r.domain && typeof r.domain === "string")
      .map((r) => ({ host: r.domain.toLowerCase(), label: r.label || "Malware", category: r.category || "" }));
    await installDnrRules(rules);
    console.log("[PhishGuard] loaded " + threatHosts.length + " blocked domains");
  } catch (e) {
    console.warn("[PhishGuard] rule refresh failed:", e.message);
  }
}

function dnrWarningUrl(r) {
  const url = "https://" + r.domain;
  return localWarnUrl(url, {
    blocked: true,
    classification: "MALICIOUS",
    content_blocked: true,
    blockedCategory: r.category || null,
    blockedLabel: r.label || "Malware",
    blockedReason: r.category
      ? (r.label || "This category") + " websites are blocked by your organization's policy."
      : "This domain is on the blocked-sites list (malware).",
    riskScore: 100,
  });
}

async function installDnrRules(rules) {
  purgeBypasses();
  // Firefox doesn't expose declarativeNetRequest dynamic rules the same way;
  // the async precheck layer below still blocks everything without DNR.
  if (!NS.declarativeNetRequest || !NS.declarativeNetRequest.getDynamicRules) {
    return;
  }
  const existing = await NS.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);
  const addRules = [];
  const map = {};
  let i = 0;
  for (const r of rules) {
    if (!r || !r.domain) continue;
    const host = String(r.domain).toLowerCase();
    if (isBypassed(host)) continue;
    if (i >= MAX_DNR_RULES) continue;
    addRules.push({
      id: 1000 + i,
      priority: 1,
      action: { type: "redirect", redirect: { url: dnrWarningUrl(r) } },
      condition: {
        urlFilter: "||" + host + "/",
        resourceTypes: ["main_frame"],
      },
    });
    map[host] = 1000 + i;
    i += 1;
  }
  await NS.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  for (const k of Object.keys(dnrIdByHost)) delete dnrIdByHost[k];
  Object.assign(dnrIdByHost, map);
}

function matchThreat(host) {
  host = (host || "").toLowerCase();
  for (const t of threatHosts) {
    if (host === t.host || host.endsWith("." + t.host)) return t;
  }
  return null;
}

// --------------------------------------------------------------------------
// Per-navigation precheck
// --------------------------------------------------------------------------
NS.webNavigation.onBeforeNavigate.addListener(
  onNavigate,
  { url: [{ schemes: ["http", "https"] }] }
);

function onNavigate(details) {
  if (details.frameId !== 0) return;
  if (isPaused()) return;
  let u;
  try { u = new URL(details.url); } catch (e) { return; }
  const origin = base();
  if (origin && u.origin === origin) return; // never block the platform itself
  if (u.protocol !== "http:" && u.protocol !== "https:") return;
  if (isBypassed(u.hostname)) return; // user clicked "continue anyway"

  const threat = matchThreat(u.hostname);
  if (threat) {
    const verdict = {
      blocked: true,
      classification: "MALICIOUS",
      content_blocked: true,
      blockedCategory: threat.category || null,
      blockedLabel: threat.label,
      blockedReason: threat.category
        ? threat.label + " websites are blocked by your organization's policy."
        : "This domain is on the blocked-sites list (malware).",
      riskScore: 100,
    };
    setCache(u.hostname, verdict);
    redirectToWarning(details.tabId, details.url, verdict, u.hostname);
    return;
  }

  const cached = getCache(u.hostname);
  if (cached) {
    const should = cached.blocked ||
      (cfg.blockSuspicious && cached.classification === "SUSPICIOUS");
    if (should) redirectToWarning(details.tabId, details.url, cached, u.hostname);
    return;
  }

  checkUrl(details.url, details.tabId, u.hostname);
}

function checkUrl(url, tabId, host) {
  if (inFlight.has(url)) return;
  const p = fetchJSON(cfg.server + "/api/analyze/precheck", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url }),
  })
    .then((d) => {
      const verdict = {
        blocked: !!d.blocked,
        classification: d.classification || "UNKNOWN",
        content_blocked: !!d.content_blocked,
        blockedCategory: d.blocked_category || null,
        blockedLabel: d.blocked_label || null,
        blockedReason: d.blocked_reason || null,
        riskScore: d.risk_score,
      };
      setCache(host, verdict);
      const should = verdict.blocked ||
        (cfg.blockSuspicious && verdict.classification === "SUSPICIOUS");
      if (should) redirectToWarning(tabId, url, verdict, host);
    })
    .catch((e) => {
      if (e && e.name !== "AbortError") console.warn("[PhishGuard] precheck failed:", e.message);
    })
    .finally(() => inFlight.delete(url));
  inFlight.set(url, p);
}

let activeTab = -1; // the tab we're currently bouncing to a warning
function redirectToWarning(tabId, targetUrl, verdict, host) {
  const warnUrl = localWarnUrl(targetUrl, verdict);
  NS.tabs.get(tabId).then((tab) => {
    if (tab && isWarningPage(tab.url)) return;
    activeTab = tabId;
    return NS.tabs.update(tabId, { url: warnUrl });
  }).then(() => {
    recordBlock(host, verdict);
  }).catch(() => { /* tab closed mid-flight */ });
}

function isWarningPage(u) {
  try { return new URL(u).pathname.indexOf(WARNING_PAGE) !== -1; } catch (e) { return false; }
}

function localWarnUrl(targetUrl, verdict) {
  // Same helper as the DNR builder so both layers point at one interstitial.
  const q = new URLSearchParams();
  q.set("blocked", "1");
  q.set("url", targetUrl);
  if (verdict.blockedReason) q.set("reason", verdict.blockedReason.slice(0, 500));
  if (verdict.blockedLabel) q.set("label", verdict.blockedLabel.slice(0, 120));
  if (verdict.blockedCategory) q.set("category", verdict.blockedCategory);
  if (verdict.riskScore != null) q.set("score", String(verdict.riskScore));
  q.set("classification", verifyClass(verdict));
  if (verdict.matchedDomain) q.set("impersonates", verdict.matchedDomain);
  return NS.runtime.getURL(WARNING_PAGE) + "?" + q.toString();
}

function verifyClass(v) {
  return v.classification || (v.blocked ? "MALICIOUS" : "SUSPICIOUS");
}

// --------------------------------------------------------------------------
// "Continue anyway" host bypass
// --------------------------------------------------------------------------
function isBypassed(host) {
  host = String(host || "").toLowerCase();
  if (!host) return false;
  const t = bypassHosts.get(host);
  if (t && t > Date.now()) return true;
  if (t) {
    bypassHosts.delete(host);
    removeDnrFor(host);
  }
  return false;
}

function purgeBypasses() {
  const now = Date.now();
  for (const [h, t] of bypassHosts) {
    if (t <= now) {
      bypassHosts.delete(h);
      removeDnrFor(h);
    }
  }
}

function removeDnrFor(host) {
  if (!NS.declarativeNetRequest || !NS.declarativeNetRequest.updateDynamicRules) return;
  const id = dnrIdByHost[host];
  if (!id) return;
  delete dnrIdByHost[host];
  NS.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [id], addRules: [] }).catch(() => {});
}

function allowBypass(url) {
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return false; }
  if (!host) return false;
  bypassHosts.set(host, Date.now() + BYPASS_MS);
  removeDnrFor(host);
  return true;
}

// --------------------------------------------------------------------------
// Local caching
// --------------------------------------------------------------------------
function setCache(host, verdict) {
  verdictCache.set(host, Object.assign({ ts: Date.now() }, verdict));
  if (verdictCache.size > CACHE_MAX) {
    const oldest = verdictCache.keys().next().value;
    verdictCache.delete(oldest);
  }
}

function getCache(host) {
  const v = verdictCache.get(host);
  if (!v) return null;
  if (Date.now() - v.ts > CACHE_TTL_MS) {
    verdictCache.delete(host);
    return null;
  }
  return v;
}

// --------------------------------------------------------------------------
// Shared helpers / messaging
// --------------------------------------------------------------------------
function fetchJSON(url, opts) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  return fetch(url, Object.assign({ signal: ctl.signal }, opts))
    .then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .finally(() => clearTimeout(timer));
}

function recordBlock(host, verdict) {
  NS.storage.local.get({ totalBlocks: 0 }).then((cur) => {
    NS.storage.local.set({
      totalBlocks: (cur.totalBlocks || 0) + 1,
      lastBlock: {
        host,
        label: verdict.blockedLabel || verifyClass(verdict),
        at: new Date().toISOString(),
      },
    });
  });
}

NS.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "scan-url") {
    scanUrlNow(msg.url).then((r) => sendResponse(r)).catch((e) =>
      sendResponse({ ok: false, error: e.message }));
    return true; // async response
  }
  if (msg && msg.type === "get-status") {
    sendResponse({
      server: cfg.server, paused: isPaused(), pauseUntil: cfg.pauseUntil,
      threatCount: threatHosts.length + verdictCache.size,
      blockSuspicious: cfg.blockSuspicious,
    });
    return true;
  }
  if (msg && msg.type === "refresh-rules") {
    refreshRules().then(() =>
      sendResponse({ ok: true, count: threatHosts.length })
    ).catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (msg && msg.type === "allow-host") {
    sendResponse({ ok: allowBypass(msg.url || "") });
    return true;
  }
  if (msg && msg.type === "continue-to") {
    allowBypass(msg.url || "");
    const tabId = sender && sender.tab ? sender.tab.id : null;
    const go = tabId != null
      ? NS.tabs.update(tabId, { url: msg.url })
      : Promise.reject(new Error("no tab context"));
    go.then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  sendResponse({ ok: false, error: "unknown message type" });
  return true;
});

async function scanUrlNow(url) {
  const u = new URL(url);
  const cached = getCache(u.hostname);
  if (cached) return { ok: true, cached: true, verdict: cached };
  const d = await fetchJSON(cfg.server + "/api/analyze/precheck", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const verdict = {
    blocked: !!d.blocked,
    classification: d.classification || "UNKNOWN",
    content_blocked: !!d.content_blocked,
    blockedCategory: d.blocked_category || null,
    blockedLabel: d.blocked_label || null,
    blockedReason: d.blocked_reason || null,
    riskScore: d.risk_score,
  };
  setCache(u.hostname, verdict);
  return { ok: true, cached: false, verdict };
}