/* PhishGuard popup. */
"use strict";

// Firefox exposes the promise-based API under `browser`; Chrome (MV3) uses
// `chrome`. Pick whichever exists.
const NS = (typeof browser !== "undefined" && browser) ? browser : chrome;

const $ = (id) => document.getElementById(id);

function send(msg, attempts) {
  attempts = attempts || 3;
  return NS.runtime.sendMessage(msg).catch((err) => {
    // Cold-start race: the event page may still be waking up right after load.
    if (attempts > 1 && err && /Receiving end|message port|establish/i.test(String(err.message || err))) {
      return new Promise((resolve) => setTimeout(resolve, 400))
        .then(() => send(msg, attempts - 1));
    }
    throw err;
  }).catch((e) => {
    throw new Error(e && e.message ? e.message : "background unavailable");
  });
}

function fmtCount(n) {
  return (n == null ? "…" : n + (n === 1 ? " domain" : " domains"));
}

async function refresh() {
  try {
    const st = await send({ type: "get-status" });
    $("server").textContent = (st.server || "").replace(/^https?:\/\//, "");
    $("threat-count").textContent = fmtCount(st.threatCount);
    $("pause-state").innerHTML = st.paused
      ? '<span class="paused">Paused until ' + new Date(st.pauseUntil).toLocaleTimeString() + "</span>"
      : '<span class="ok">Active</span>';
    $("pause").textContent = st.paused ? "Resume protection" : "Pause for 15 minutes";
  } catch (e) {
    $("threat-count").textContent = "?";
    $("pause-state").innerHTML = '<span class="bad">Background error</span>';
  }
  NS.storage.local.get({ lastBlock: null }).then((cur) => {
    if (cur.lastBlock) {
      $("last-block").innerHTML =
        "<div><b>" + esc(cur.lastBlock.host) + "</b> — " + esc(cur.lastBlock.label) + "</div>" +
        '<div class="muted">' + esc(new Date(cur.lastBlock.at).toLocaleString()) + "</div>";
    }
  });
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

$("pause").addEventListener("click", async () => {
  const cur = await send({ type: "get-status" });
  const now = Date.now();
  const pauseUntil = cur.paused ? 0 : now + 15 * 60 * 1000;
  await NS.storage.local.set({ pauseUntil });
  refresh();
});

$("scan").addEventListener("click", async () => {
  const out = $("scan-result");
  out.textContent = "Checking…";
  out.className = "scanline";
  try {
    const [tab] = await NS.tabs.query({ active: true, currentWindow: true });
    const res = await send({ type: "scan-url", url: tab.url });
    const v = res.verdict;
    if (v.blocked || v.classification === "SUSPICIOUS") {
      out.innerHTML = '<span class="bad">' + esc(v.classification) + " (" + (v.riskScore ?? "?") +
        ") — blocked: " + (v.blocked ? "yes" : "no, allowlisted at your settings") +
        (v.blockedLabel ? " · " + esc(v.blockedLabel) : "") + "</span>";
    } else {
      out.innerHTML = '<span class="ok">' + esc(v.classification) + " (" + (v.riskScore ?? "?") + ") — safe</span>";
    }
  } catch (e) {
    out.innerHTML = '<span class="bad">Check failed: ' + esc(e.message) + "</span>";
  }
});

$("opts").addEventListener("click", () => NS.runtime.openOptionsPage());

refresh();