/* PhishGuard options page. */
"use strict";

// Firefox exposes the promise-based API under `browser`; Chrome (MV3) uses
// `chrome`. Pick whichever exists.
const NS = (typeof browser !== "undefined" && browser) ? browser : chrome;

const $ = (id) => document.getElementById(id);
const statusEl = $("status");

window.addEventListener("error", (e) => {
  const msg = "Page error: " + (e.message || "unknown") + " @ " + (e.filename || "") + ":" + e.lineno;
  if (statusEl) { statusEl.textContent = msg; statusEl.className = "status err"; }
  try { alert(msg); } catch (x) { /* popups may block alert */ }
});

window.addEventListener("unhandledrejection", (e) => {
  const msg = "Async error: " + ((e.reason && e.reason.message) || String(e.reason));
  if (statusEl) { statusEl.textContent = msg; statusEl.className = "status err"; }
  try { alert(msg); } catch (x) { /* ignore */ }
});

function say(msg, kind) {
  if (statusEl) {
    statusEl.textContent = msg;
    statusEl.className = "status " + (kind || "");
  }
}

function send(msg) {
  return NS.runtime.sendMessage(msg).catch((e) => {
    throw new Error(e && e.message ? e.message : "background not responding");
  });
}

function normalizeServer(raw) {
  let s = String(raw || "").trim();
  if (!s) return "";
  if (!/^https?:\/\//i.test(s)) s = "http://" + s;
  return s.replace(/\/+$/, "") || s;
}

function populate(raw) {
  $("server").value = normalizeServer((raw && raw.server) || "http://192.168.100.43:8000");
  $("susp").checked = !!(raw && raw.blockSuspicious);
  const stored = (raw && raw.server) ? 'stored server: "' + raw.server + '"' : "no server stored yet (using default)";
  const diag = $("diag");
  if (diag) diag.textContent = stored;
}

NS.storage.local.get(null).then(populate).catch(() => populate({}));

/* Save — never depends on the background. Storage first, refresh is best-effort. */
$("save").addEventListener("click", async () => {
  const server = normalizeServer($("server").value);
  if (!server) {
    say("Enter the server address, e.g. http://192.168.100.43:8000", "err");
    return;
  }
  let ok = false;
  try {
    const u = new URL(server);
    ok = (u.protocol === "http:" || u.protocol === "https:") && !!u.hostname;
  } catch (ignored) { ok = false; }
  if (!ok) {
    say('"' + server + '" is not a valid address. Example: http://192.168.100.43:8000', "err");
    return;
  }
  try {
    await NS.storage.local.set({ server, blockSuspicious: $("susp").checked });
  } catch (e) {
    say("Storage error: " + e.message, "err");
    return;
  }
  say('Saved: "' + server + '". Loading blacklist…', "ok");
  const diag = $("diag");
  if (diag) diag.textContent = 'stored server: "' + server + '"';
  send({ type: "refresh-rules" })
    .then((r) => {
      if (diag) diag.textContent = 'stored server: "' + server + '" · ' + r.count + " domains protected";
    })
    .catch(() => { /* background will refresh on its own timer / next browser start */ });
});

$("test").addEventListener("click", () => {
  const server = normalizeServer($("server").value);
  if (!server) {
    say("Enter the server address first, e.g. http://192.168.100.43:8000", "err");
    return;
  }
  say("Testing " + server + " …");
  fetch(server + "/api/analyze/precheck", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://paypa1-secure.com/login" }),
  }).then((r) => {
    if (!r.ok) throw new Error("HTTP " + r.status + " from the server");
    return r.json();
  }).then((d) => {
    const blocked = d.blocked ? "BLOCKED — connection works" : "not blocked (check server config)";
    say("Server reachable — sample malware verdict: " + blocked, d.blocked ? "ok" : "err");
  }).catch((e) => say("Connection failed: " + e.message, "err"));
});

$("refresh").addEventListener("click", () => {
  say("Refreshing…");
  send({ type: "refresh-rules" })
    .then((r) => say(r.ok ? "Done — " + r.count + " domains protected." : "Failed: " + r.error,
        r.ok ? "ok" : "err"))
    .catch((e) => say("Background not running: " + e.message + " — it refreshes on browser start anyway.", "err"));
});