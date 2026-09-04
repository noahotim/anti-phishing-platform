/* Employee URL checker page. */
(function () {
  "use strict";

  var CLS_BANNER = {
    SAFE: "banner-safe",
    SUSPICIOUS: "banner-susp",
    MALICIOUS: "banner-mal",
    UNKNOWN: "banner-unk",
  };
  var GAUGE_COLOR = {
    SAFE: "#22c55e",
    SUSPICIOUS: "#f59e0b",
    MALICIOUS: "#ef4444",
    UNKNOWN: "#5b6c88",
  };
  var lastResult = null;

  UI.boot().then(function (user) {
    if (user && (user.role === "ADMIN" || user.role === "SUPER_ADMIN" ||
                 user.role === "SECURITY_ANALYST")) {
      var tool = document.getElementById("email-tool");
      tool.classList.remove("hidden");
      tool.innerHTML =
        '<div class="card"><h2>Email analyzer</h2>' +
        '<p class="sub">Paste a message (or the important headers) for sender / link / keyword analysis.</p>' +
        '<form id="email-form">' +
        '<label>From header</label>' +
        '<input type="text" id="e-from" placeholder="Security &lt;noreply@example.com&gt;">' +
        '<div class="two-col" style="grid-template-columns:1fr 1fr;gap:0 14px;">' +
        '<div><label>Subject</label><input type="text" id="e-subject" placeholder="Your invoice is ready"></div>' +
        '<div><label>Reply-To (optional)</label><input type="text" id="e-reply" placeholder="hr@company-example.com"></div>' +
        '</div>' +
        '<label>Body</label><textarea id="e-body" rows="3" placeholder="Paste the message text. Continue here."></textarea>' +
        '<label>Links found in the message (one per line: visible text = actual URL)</label>' +
        '<textarea id="e-links" rows="2" placeholder="example.com = https://examp1e.com/login"></textarea>' +
        '<button type="submit" class="btn-primary" style="margin-top:12px;">Analyze email</button>' +
        '</form>' +
        '<div id="email-result" class="hidden" style="margin-top:16px;"></div></div>';
      tool.querySelector("#email-form").addEventListener("submit", analyzeEmail);
    }
  });

  function showSpinner() {
    document.getElementById("scan-btn").innerHTML =
      '<span class="spin"></span> Analyzing';
    document.getElementById("scan-btn").disabled = true;
  }
  function stopSpinner() {
    document.getElementById("scan-btn").textContent = "Analyze";
    document.getElementById("scan-btn").disabled = false;
  }

  document.getElementById("checker-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var url = document.getElementById("url-input").value.trim();
    if (!url) return;
    showSpinner();
    document.getElementById("result").classList.add("hidden");
    document.getElementById("report-panel").classList.add("hidden");
    API.analyzeUrl(url)
      .then(function (r) {
        lastResult = r;
        renderResult(r);
        stopSpinner();
      })
      .catch(function (err) {
        UI.toast(err.message || "Analysis failed", "err");
        stopSpinner();
      });
  });

  function renderResult(r) {
    var el = document.getElementById("result");
    var clsTxt = r.classification || "UNKNOWN";
    var banner = CLS_BANNER[clsTxt] || CLS_BANNER.UNKNOWN;
    var bannerMsg;
    if (clsTxt === "SAFE") bannerMsg = "This URL is an approved, trusted destination.";
    else if (clsTxt === "SUSPICIOUS") bannerMsg = "This URL has suspicious signals. Verify the sender before clicking.";
    else if (clsTxt === "MALICIOUS") bannerMsg = "This URL is likely a phishing attempt. Do not visit it.";
    else bannerMsg = "Cannot safely classify this URL. It is not an approved destination.";

    var intel = r.threat_intel || [];
    var reasons = (r.reasons || []);
    var reasonsHtml = reasons.length
      ? reasons.map(function (x) { return "<li>" + UI.esc(x) + "</li>"; }).join("")
      : '<li class="muted">No suspicious signals detected.</li>';

    var matched = r.matched_domain
      ? "<dt>Impersonates</dt><dd><strong>" + UI.esc(r.matched_domain) + "</strong></dd>"
      : "";

    var intelHtml = intel.length
      ? "<dt>Threat intel</dt><dd>" + intel.map(function (t) {
          return '<code>' + UI.esc(t.source || "intel") + "</code> &middot; " +
            UI.esc(t.verdict || "");
        }).join("; ") + "</dd>"
      : "";

    el.innerHTML =
      '<div class="card result-banner ' + banner + '">' +
      '  <div class="head-row">' +
      UI.badge(r.classification) +
      '    <span class="small muted" style="margin-left:auto;">Host ' + r.hostname + "</span>" +
      "  </div>" +
      '  <div style="margin-top:14px;" class="gauge-wrap">' +
      '    <div class="gauge" style="--p:' + (r.risk_score || 0) + ";--gauge-color:" +
        (GAUGE_COLOR[clsTxt] || GAUGE_COLOR.UNKNOWN) + ';">' +
      '      <div class="val">' + (r.risk_score || 0) + "</div></div>" +
      "    <div>" +
      "      <div style=\"font-size:17px;font-weight:700;margin-bottom:4px;\">" +
            clsTxt + " &middot; " + UI.esc(bannerMsg) + "</div>" +
      '      <div class="small muted">Score scale 0–100.</div>' +
      "    </div></div>" +
      '  <ul class="reasons">' + reasonsHtml + "</ul>" +
      '  <dl class="list-detail" style="grid-template-columns:150px 1fr;">' +
      "    <dt>URL</dt><dd class=\"mono\">" + UI.esc(r.url) + "</dd>" +
      "    <dt>Hostname</dt><dd class=\"mono\">" + UI.esc(r.hostname) + "</dd>" +
      "    <dt>Registered domain</dt><dd class=\"mono\">" + UI.esc(r.registered_domain) + "</dd>" +
      (r.tld ? "<dt>TLD</dt><dd class=\"mono\">" + UI.esc(r.tld) + "</dd>" : "") +
      matched + intelHtml +
      "  </dl>" +
      "</div>";
    document.getElementById("result").classList.remove("hidden");

    document.getElementById("report-panel").classList.remove("hidden");
    document.getElementById("report-msg").textContent = "";
    document.getElementById("report-comment").value = "";
  }

  document.getElementById("report-btn").addEventListener("click", function () {
    if (!lastResult) return;
    var btn = document.getElementById("report-btn");
    btn.disabled = true;
    var msg = document.getElementById("report-msg");
    API.reportUrl(lastResult.url, document.getElementById("report-comment").value.trim())
      .then(function () {
        msg.textContent = "Report submitted. Thank you — the team will review it.";
        UI.toast("Report submitted", "ok");
      })
      .catch(function (err) {
        msg.textContent = "";
        UI.toast(err.message || "Could not submit report", "err");
      })
      .finally(function () { btn.disabled = false; });
  });

  function linkList(raw) {
    var out = [];
    (raw || "").split("\n").forEach(function (line) {
      line = line.trim();
      if (!line) return;
      var eq = line.indexOf("=");
      if (eq > 0) {
        out.push({ text: line.slice(0, eq).trim(), href: line.slice(eq + 1).trim() });
      } else {
        out.push({ text: "", href: line });
      }
    });
    return out;
  }

  function analyzeEmail(e) {
    e.preventDefault();
    var btn = e.target.querySelector("[type=submit]");
    btn.disabled = true;
    var links = linkList(document.getElementById("e-links").value);
    var payload = {
      from_header: document.getElementById("e-from").value.trim(),
      reply_to: document.getElementById("e-reply").value.trim(),
      subject: document.getElementById("e-subject").value.trim(),
      body: document.getElementById("e-body").value,
      links: links,
      attachments: [],
    };
    API.analyzeEmail(payload)
      .then(function (r) { renderEmailResult(r); })
      .catch(function (err) { UI.toast(err.message || "Email analysis failed", "err"); })
      .finally(function () { btn.disabled = false; });
  }

  function renderEmailResult(r) {
    var el = document.getElementById("email-result");

    var mismatches = (r.display_mismatches || []).map(function (l) {
      return "<li>Text <code>" + UI.esc(l.display_text) + "</code> leads to host " +
        "<code>" + UI.esc(l.hostname) + "</code></li>";
    }).join("");
    var links = (r.link_findings || []).filter(function (l) { return l.risk_score > 0; })
      .map(function (l) {
        return "<li><code>" + UI.esc(l.url || l.hostname) + "</code> &middot; " +
          UI.badge(l.classification || "UNKNOWN") + " " + UI.esc(l.reasons.join("; ")) + "</li>";
      }).join("");
    var kws = (r.keyword_hits || []).length
      ? "<li>Keywords: " + r.keyword_hits.map(UI.esc).join(", ") + "</li>" : "";
    var atts = (r.attachment_risks || []).length
      ? "<li>Risky attachments: " + r.attachment_risks.map(UI.esc).join(", ") + "</li>" : "";
    var imp = r.impersonates
      ? "<li>Sender impersonates <strong>" + UI.esc(r.impersonates) + "</strong></li>" : "";

    el.classList.remove("hidden");
    el.innerHTML =
      '<div class="card result-banner ' + (CLS_BANNER[r.classification] || CLS_BANNER.UNKNOWN) + '">' +
      '  <div class="head-row">' +
      UI.badge(r.classification || "UNKNOWN") +
      '  <span class="small muted" style="margin-left:auto;">Sender ' + UI.esc(r.sender_domain || "—") +
      (r.reply_to_domain ? " · Reply-To " + UI.esc(r.reply_to_domain) : "") + "</span></div>" +
      '  <div style="margin-top:12px;" class="gauge-wrap">' +
      '    <div class="gauge" style="--p:' + (r.risk_score || 0) + ";--gauge-color:" +
        (GAUGE_COLOR[r.classification] || GAUGE_COLOR.UNKNOWN) + ';">' +
      '      <div class="val">' + (r.risk_score || 0) + "</div></div>" +
      "    <div><div class=\"small muted\">Overall email risk score 0–100.</div></div></div>" +
      '  <ul class="reasons">' +
      imp + kws + mismatches + links + atts +
      (r.reasons || []).map(function (x) { return "<li>" + UI.esc(x) + "</li>"; }).join("") +
      "  </ul></div>";
  }
})();