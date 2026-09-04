/* Warning interstitial for blocked/fragile links. */
(function () {
  "use strict";

  var params = new URLSearchParams(window.location.search);
  var target = params.get("url") || "";
  var scanId = params.get("scan_id") || null;

  var CAT_LABELS = {
    GAMBLING: "Gambling / betting",
    ADULT: "Adult content",
    SOCIAL_MEDIA: "Social media",
    OTHER: "Blocked content",
  };

  function render(scan, fallbackUrl) {
    var url = (scan && scan.url) || fallbackUrl || target;
    var cls = (scan && scan.classification) || "MALICIOUS";
    var score = scan ? scan.risk_score : "—";
    var reasons = (scan && scan.reasons) || [];
    var policyCat = scan && scan.blocked_category ? (CAT_LABELS[scan.blocked_category] || scan.blocked_category) : null;

    document.getElementById("warn-title").textContent =
      scan && scan.content_blocked
        ? "Access blocked by organization policy"
        : "Warning: this link is flagged as unsafe";

    if (scan && scan.content_blocked && policyCat) {
      document.getElementById("warn-sub").textContent =
        policyCat + " websites are blocked by your organization's settings.";
    }

    var badge;
    if (scan && scan.content_blocked) {
      badge = '<span class="bdg-mal">POLICY BLOCK</span>';
    } else {
      badge = cls === "MALICIOUS"
        ? '<span class="bdg-mal">MALICIOUS</span>'
        : '<span class="bdg-susp">SUSPICIOUS</span>';
    }
    document.getElementById("warn-badge").innerHTML = badge;

    var icon = document.querySelector(".warn-icon");
    icon.className = "warn-icon " + (cls === "MALICIOUS" ? "critical" : "warn");

    var body = '<p class="mono" style="margin-top:6px;word-break:break-all;">' +
      UI.esc(url) + "</p>" +
      '<dl class="list-detail" style="max-width:560px;margin:16px auto 0;grid-template-columns:120px 1fr;">' +
      "<dt>Risk score</dt><dd><strong>" + score + "</strong> / 100</dd>" +
      (scan && scan.matched_domain
        ? "<dt>Impersonates</dt><dd class=\"mono\">" + UI.esc(scan.matched_domain) + "</dd>" : "") +
      "</dl>";
    if (reasons.length) {
      body += '<ul class="reasons" style="text-align:left;max-width:560px;margin:8px auto 0;">' +
        reasons.map(function (x) { return "<li>" + UI.esc(x) + "</li>"; }).join("") + "</ul>";
    }
    document.getElementById("warn-body").innerHTML = body;
  }

  function renderFromParams() {
    var category = params.get("category") || "";
    var pseudo = {
      url: params.get("url") || target,
      classification: params.get("classification") || (category ? "MALICIOUS" : "MALICIOUS"),
      risk_score: parseInt(params.get("score") || "100", 10),
      content_blocked: !!category,
      blocked_category: category || null,
      matched_domain: params.get("impersonates") || null,
      reasons: [params.get("reason")].filter(Boolean),
    };
    render(pseudo, pseudo.url);
  }

  UI.boot().then(function (user) {
    var allowed = user && (user.role === "ADMIN" || user.role === "SUPER_ADMIN" ||
      user.role === "SECURITY_ANALYST");
    var advance = document.getElementById("warn-advance");
    if (!allowed) {
      advance.classList.add("hidden");
      document.getElementById("warn-sub").textContent =
        "This link was flagged. Do not continue unless you verified it directly " +
        "with the security team.";
    } else {
      advance.classList.remove("hidden");
      advance.addEventListener("click", function () { window.close(); });
    }
    document.getElementById("warn-back").addEventListener("click", function () {
      window.history.length > 1 ? window.history.back() : window.location.assign("/app/index.html");
    });

    if (scanId) {
      API.getScan(scanId).then(function (s) { render(s, ""); })
        .catch(function () { render(null, decodeURIComponent(params.get("url") || "")); });
    } else if (params.get("blocked")) {
      renderFromParams();
    } else {
      render(null, decodeURIComponent(target));
    }
  }).catch(function () { /* boot() redirects when sign-in required */ });
})();