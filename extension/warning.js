/* PhishGuard interstitial (extension-hosted) — lets the user continue anyway. */
"use strict";

// Firefox exposes the promise-based API under `browser`; Chrome (MV3) uses
// `chrome`. Pick whichever exists.
const NS = (typeof browser !== "undefined" && browser) ? browser : chrome;

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(window.location.search);
const target = params.get("url") || "";

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function status(msg, kind) {
  const el = $("status");
  el.textContent = msg || "";
  el.className = "status " + (kind || "");
}

const classification = params.get("classification") || "MALICIOUS";
const category = params.get("category") || "";
const label = params.get("label") || params.get("reason") || "";
const reason = params.get("reason") || "";
const score = params.get("score") || "";
const impersonates = params.get("impersonates") || "";

$("badge").textContent = category ? "POLICY BLOCK" : classification;
$("badge").className = "badge " + (classification === "SUSPICIOUS" ? "bdg-susp" : "bdg-mal");
$("warn-icon").className = "warn-icon " + (classification === "SUSPICIOUS" ? "warn" : "critical");
$("title").textContent = category ? "Access blocked by policy" : "Warning: this link is flagged as unsafe";
$("sub").textContent = category
  ? (label ? label + " websites are blocked by your organization's settings." : "This site is blocked by policy.")
  : "PhishGuard flagged this link as " + classification.toLowerCase() + ".";
$("url").textContent = target;
$("score").textContent = score || "100";

if (category) {
  $("cat-chip").style.display = "";
  $("cat").textContent = category;
}
if (impersonates) {
  $("imp-chip").style.display = "";
  $("imp").textContent = impersonates;
}
if (reason) {
  $("reason").style.display = "";
  $("reason").textContent = reason;
}
if (label) $("sub").textContent = label;

function send(msg, attempts) {
  attempts = attempts || 3;
  return NS.runtime.sendMessage(msg).catch((err) => {
    if (attempts > 1 && err && /Receiving end|message port|establish/i.test(String(err.message || err))) {
      return new Promise((resolve) => setTimeout(resolve, 400)).then(() => send(msg, attempts - 1));
    }
    throw err;
  });
}

$("back").addEventListener("click", () => {
  if (window.history.length > 1) window.history.back();
  else window.close();
});

$("continue").addEventListener("click", async () => {
  if (!target) { status("No target URL to continue to.", "err"); return; }
  status("Continuing…");
  $("continue").disabled = true;
  try {
    const r = await send({ type: "continue-to", url: target });
    if (!r || !r.ok) throw new Error((r && r.error) || "extension did not respond");
    status("", "ok");
  } catch (e) {
    status("Could not continue: " + e.message, "err");
    $("continue").disabled = false;
  }
});