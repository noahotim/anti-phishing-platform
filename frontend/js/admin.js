/* Admin / analyst console. */
(function () {
  "use strict";

  var me = null;
  var editingDomain = null;
  var ABLE = { overview: false, reports: false, domains: false, blocked: false, audit: false, users: false, settings: false };
  var NOTE = {
    overview: "Dashboard access is limited to analysts and administrators.",
    reports: "Analysts and administrators can review phishing reports.",
    domains: "Only administrators manage trusted domains.",
    blocked: "Only administrators manage blocked sites and the content policy.",
    audit: "Only administrators can view the audit log.",
    users: "Only super admins manage user accounts.",
    settings: "Only administrators change risk thresholds.",
  };

  UI.boot(["SECURITY_ANALYST", "ADMIN", "SUPER_ADMIN"]).then(function (u) {
    me = u;
    ABLE.overview = true;
    ABLE.reports = true;
    if (u.role === "ADMIN" || u.role === "SUPER_ADMIN") {
      ABLE.domains = true;
      ABLE.blocked = true;
      ABLE.audit = true;
      ABLE.settings = true;
    }
    ABLE.users = u.role === "SUPER_ADMIN";
    maskTabs();
    bindTabs();
    showPanel("overview");
  });

  function maskTabs() {
    document.querySelectorAll("#admin-tabs button").forEach(function (btn) {
      var name = btn.getAttribute("data-tab");
      if (!ABLE[name]) btn.classList.add("hidden");
    });
  }

  function bindTabs() {
    document.querySelectorAll("#admin-tabs button").forEach(function (btn) {
      btn.addEventListener("click", function () { showPanel(btn.getAttribute("data-tab")); });
    });
  }

  function showPanel(name) {
    document.querySelectorAll("#admin-tabs button").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-tab") === name);
    });
    var view = document.getElementById("views");
    if (!ABLE[name]) {
      view.innerHTML = '<div class="card"><div class="empty">' + NOTE[name] + "</div></div>";
      return;
    }
    if (name === "overview") renderOverview(view);
    else if (name === "reports") renderReports(view);
    else if (name === "domains") renderDomains(view);
    else if (name === "blocked") renderBlocked(view);
    else if (name === "audit") renderAudit(view);
    else if (name === "users") renderUsers(view);
    else if (name === "settings") renderSettings(view);
  }

  /* ===================== Overview ===================== */
  function renderOverview(view) {
    view.innerHTML = '<div class="empty"><span class="spin"></span> Loading dashboard…</div>';
    API.dashboardStats(30).then(function (d) {
      var kpi = [
        ["Total scans (30d)", d.total_scans, d.total_scans + " in last 30 days", ""],
        ["Blocked / suspicious", d.blocked, "MALICIOUS + SUSPICIOUS combined", "text-warn"],
        ["Safe", d.safe, "approved destinations", "text-safe"],
        ["Malicious", d.malicious, "high confidence attacks", "text-mal"],
      ];
      var kpiHtml = kpi.map(function (k) {
        return '<div class="kpi"><div class="label">' + k[0] + '</div>' +
          '<div class="value ' + k[3] + '">' + k[1] + "</div>" +
          '<div class="foot">' + k[2] + "</div></div>";
      }).join("");

      var trend = (d.trend || []);
      var maxV = Math.max(1, trend.reduce(function (m, t) { return Math.max(m, t.total); }, 1));
      var trendHtml = trend.map(function (t) {
        var bad = t.blocked || 0;
        var hTot = Math.round((t.total / maxV) * 100);
        var hBad = Math.round((bad / maxV) * 100);
        return '<div class="bar-col"><div class="bar-tip">' + t.total + "</div>" +
          '<div class="bar bad" style="height:' + hBad + 'px;max-height:120px;"></div>' +
          '<div class="bar" style="height:' + (hTot - hBad) + 'px;max-height:120px;"></div>' +
          '<div class="lbl">' + (t.date ? t.date.slice(5) : "") + "</div></div>";
      }).join("") || '<div class="empty">No scans yet this period.</div>';

      var impHtml = (d.top_impersonated || []).map(function (r) {
        return "<tr><td class=\"mono\">" + UI.esc(r.domain) + "</td>" +
          "<td>" + r.count + "</td></tr>";
      }).join("") || '<tr><td colspan="2" class="empty">No impersonation detected yet.</td></tr>';

      var distHtml = (d.risk_distribution || []).map(function (b) {
        var pct = d.total_scans ? Math.round((b.count / d.total_scans) * 100) : 0;
        return '<div class="legend" style="display:block;margin-bottom:8px;">' +
          '<span class="small" style="min-width:150px;">Score ' + b.label + "</span>" +
          '<code>' + b.count + "</code>" +
          '<div class="bar" style="height:6px;width:' + pct + '%;display:inline-block;margin-left:8px;"></div>' +
          "</div>";
      }).join("") || '<div class="empty">No data.</div>';

      var recentHtml = (d.recent_scans || []).slice(0, 10).map(function (r) {
        return "<tr><td class=\"mono\">" + UI.esc(r.url.length > 60 ? r.url.slice(0, 60) + "…" : r.url) + "</td>" +
          "<td>" + UI.badge(r.classification) + "</td>" +
          "<td>" + r.risk_score + "</td>" +
          "<td class=\"mono small muted\">" + UI.esc(r.matched_domain || "—") + "</td>" +
          "<td class=\"small muted\">" + UI.fmtDate(r.created_at) + "</td></tr>";
      }).join("") || '<tr><td colspan="5" class="empty">No scans yet.</td></tr>';

      var srcHtml = (d.sources || []).map(function (s) {
        return '<span class="type-badge">' + UI.esc(s.source) + " &middot; " + s.count + "</span>";
      }).join(" ") || '<span class="muted">—</span>';

      view.innerHTML =
        '<div class="grid-4">' + kpiHtml + "</div>" +
        '<div class="card" style="margin-top:22px;">' +
        '  <div class="head-row"><h2>Live threat feed</h2>' +
        '  <button class="btn btn-sm" id="ti-sync">Sync now</button></div>' +
        '  <div id="ti-body"><span class="spin" style="display:block;margin:14px auto;"></span></div>' +
        "</div>" +
        '<div class="card" style="margin-top:22px;">' +
        '  <div class="head-row"><h2>Daily scan trend</h2>' +
        '  <div class="legend" style="margin-left:auto;">' +
        '    <span><span class="swatch" style="background:#ef4444;"></span>blocked</span>' +
        '    <span><span class="swatch" style="background:#4f8cff;"></span>safe</span></div></div>' +
        '  <div class="bar-chart">' + trendHtml + '</div></div>' +
        '<div class="grid-2" style="margin-top:22px;">' +
        '  <div class="card"><h2>Risk score distribution</h2>' +
        '  <div style="margin-top:12px;">' + distHtml + "</div></div>" +
        '  <div class="card"><h2>Top impersonated domains</h2>' +
        '  <div class="table-scroll" style="margin-top:8px;"><table><thead>' +
        '    <tr><th>Domain</th><th>Hits</th></tr></thead><tbody>' + impHtml +
        "  </tbody></table></div></div></div>" +
        '<div class="card" style="margin-top:22px;">' +
        '  <div class="head-row"><h2>Recent scans</h2>' +
        '  <div class="legend" style="margin-left:auto;">' + srcHtml + "</div></div>" +
        '  <div class="table-scroll" style="margin-top:8px;"><table><thead>' +
        '    <tr><th>URL</th><th>Verdict</th><th>Score</th><th>Impersonates</th><th>When</th></tr></thead>' +
        "  <tbody>" + recentHtml + "</tbody></table></div></div>";
      fillTI();
    }).catch(function (err) {
      view.innerHTML = '<div class="card"><div class="empty">' + UI.esc(err.message) + "</div></div>";
    });
  }

  function fillTI() {
    var body = document.getElementById("ti-body");
    if (!body) return;
    API.threatIntelStatus().then(function (ti) {
      var rows = [
        ["Source", ti.feed],
        ["Sync interval", ti.sync_interval_minutes + " min"],
        ["Known malicious hosts", ti.known_threats],
        ["Last sync", ti.last_sync ? UI.fmtDate(ti.last_sync) : "never"],
        ["Per-scan providers", ti.per_scan_providers_enabled ? "enabled" : "disabled (keyless feed)"],
      ];
      body.innerHTML = rows.map(function (r) {
        return '<span class="ti-stat"><span class="small muted">' + r[0] + "</span>" +
          "<b>" + UI.esc(String(r[1])) + "</b></span>";
      }).join("");
      var btn = document.getElementById("ti-sync");
      if (btn) btn.addEventListener("click", syncTI);
    }).catch(function (err) {
      body.innerHTML = '<span class="empty">' + UI.esc(err.message) + "</span>";
    });
  }

  function syncTI() {
    var btn = document.getElementById("ti-sync");
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    btn.textContent = "Syncing…";
    API.syncThreatIntel().then(function (r) {
      UI.toast("Feed synced: " + r.added + " new malicious hosts", "ok");
      return API.threatIntelStatus();
    }).then(function (ti) {
      var body = document.getElementById("ti-body");
      if (body) body.innerHTML =
        '<span class="ti-stat"><span class="small muted">Known malicious hosts</span>' +
        '<b>' + ti.known_threats + "</b></span>" +
        '<span class="ti-stat"><span class="small muted">Last sync</span>' +
        '<b>' + (ti.last_sync ? UI.fmtDate(ti.last_sync) : "never") + "</b></span>";
    }).catch(function (err) {
      UI.toast(err.message || "Sync failed", "err");
    }).finally(function () {
      if (btn) { btn.disabled = false; btn.textContent = "Sync now"; }
    });
  }

  /* ===================== Reports ===================== */
  var STATUSES = ["NEW", "INVESTIGATING", "CONFIRMED_THREAT", "FALSE_POSITIVE", "RESOLVED"];

  function renderReports(view) {
    API.listReports().then(function (reports) {
      var sel = '<select id="report-status" style="width:auto;">' +
        '<option value="">All statuses</option>' +
        STATUSES.map(function (s) { return '<option>' + s + "</option>"; }).join("") + "</select>";
      view.innerHTML =
        '<div class="card"><div class="head-row"><h2>Phishing reports</h2>' +
        '<div class="filter-bar" style="margin-left:auto;">' + sel + "</div></div>" +
        '<div class="table-scroll" style="margin-top:14px;"><table><thead>' +
        '<tr><th>#</th><th>URL</th><th>Reporter</th><th>Analysis</th><th>Status</th><th>When</th><th></th></tr>' +
        "</thead><tbody id=\"report-rows\"></tbody></table></div></div>" +
        '<div id="report-detail"></div>';
      fillReports(reports, "report-rows");
      document.getElementById("report-status").addEventListener("change", function (ev) {
        var val = ev.target.value;
        view.querySelector("#report-rows").innerHTML =
          '<tr><td colspan="7" class="empty"><span class="spin"></span></td></tr>';
        API.listReports(val || "").then(function (rs) { fillReports(rs, "report-rows"); });
      });
    }).catch(function (err) {
      view.innerHTML = '<div class="card"><div class="empty">' + UI.esc(err.message) + "</div></div>";
    });
  }

  function fillReports(reports, tbodyId) {
    var tbody = document.getElementById(tbodyId);
    if (!reports.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">No reports.</td></tr>';
      return;
    }
    tbody.innerHTML = reports.map(function (r) {
      var a = r.analysis || {};
      return "<tr>" +
        "<td>" + r.id + "</td>" +
        '<td class="mono">' + UI.esc((r.url || "").slice(0, 70)) + "</td>" +
        "<td class=\"small\">" + UI.esc(r.user_id) + "</td>" +
        "<td>" + UI.badge(a.classification || "UNKNOWN") + (a.risk_score != null ? " <span class=\"small muted\">" + a.risk_score + "</span>" : "") + "</td>" +
        '<td><span class="type-badge">' + UI.esc(r.status) + "</span></td>" +
        '<td class="small muted">' + UI.fmtDate(r.created_at) + "</td>" +
        '<td><button class="btn btn-sm" data-open="' + r.id + '">Review</button></td></tr>';
    }).join("");
    tbody.querySelectorAll("[data-open]").forEach(function (btn) {
      btn.addEventListener("click", function () { openReport(Number(btn.getAttribute("data-open"))); });
    });
  }

  function openReport(id) {
    API.listReports().then(function (all) {
      var r = all.filter(function (x) { return x.id === id; })[0];
      if (!r) return;
      var a = r.analysis || {};
      var box = document.getElementById("report-detail");
      var sel = '<select id="rd-status" style="width:auto;">' +
        STATUSES.map(function (s) {
          return '<option' + (s === r.status ? " selected" : "") + ">" + s + "</option>";
        }).join("") + "</select>";
      box.innerHTML =
        '<div class="card" style="margin-top:16px;">' +
        '  <div class="head-row"><h2>Report #' + r.id + "</h2>" +
        '  <div class="row" style="margin-left:auto;">' + sel +
        '    <button class="btn btn-sm btn-primary" id="rd-save">Save status</button></div></div>' +
        "  <p class=\"sub\">Reported " + UI.fmtDate(r.created_at) + "</p>" +
        '  <p class="mono">' + UI.esc(r.url) + "</p>" +
        (r.comment ? "<p style=\"margin-top:8px;\">" + UI.esc(r.comment) + "</p>" : "") +
        '  <div class="divider"></div>' +
        UI.badge(a.classification || "UNKNOWN") +
        ' <span class="small">score ' + a.risk_score + "</span>" +
        (a.reasons && a.reasons.length ? '<ul class="reasons">' + a.reasons.map(function (x) { return "<li>" + UI.esc(x) + "</li>"; }).join("") + "</ul>" : "") +
        "</div>";
      document.getElementById("rd-save").addEventListener("click", function () {
        var status = document.getElementById("rd-status").value;
        API.updateReportStatus(r.id, status, "").then(function () {
          UI.toast("Report #" + r.id + " updated", "ok");
        }).catch(function (err) {
          UI.toast(err.message, "err");
        });
      });
    });
  }

  /* ===================== Trusted domains ===================== */
  function renderDomains(view) {
    view.innerHTML =
      '<div class="card">' +
      '  <div class="head-row"><h2>Add a trusted domain</h2></div>' +
      '  <form id="dom-form">' +
      '    <div class="grid-2">' +
      '      <div><label>Domain</label><input type="text" id="dom-domain" required placeholder="example.com"></div>' +
      '      <div><label>Category</label><input type="text" id="dom-category" value="Corporate" maxlength="64"></div>' +
      "    </div>" +
      '    <div class="check-row"><input type="checkbox" id="dom-critical">' +
      '    <label for="dom-critical">Critical brand — impersonation is weighted harder</label></div>' +
      '    <label>Allowed subdomains</label>' +
      '    <input type="text" id="dom-allowed" placeholder="*.mail.example.com" maxlength="1024">' +
      '    <label>Notes</label>' +
      '    <textarea id="dom-notes" maxlength="2000" placeholder="Purpose / owner"></textarea>' +
      '    <div class="row" style="margin-top:14px;">' +
      '      <button type="submit" class="btn-primary">Add domain</button>' +
      '      <button type="button" class="btn" id="dom-export">Export CSV</button>' +
      '      <label class="small muted" style="margin:0;display:inline-flex;align-items:center;gap:6px;">' +
      '        <input type="file" id="dom-file" accept=".csv" style="width:auto;">Import CSV</label>' +
      "    </div>" +
      "  </form></div>" +
      '<div class="card" style="margin-top:22px;"><div class="head-row"><h2>Trusted domains</h2>' +
      '  <select id="dom-cat-filter" style="width:auto;margin-left:auto;">' +
      '    <option value="">All categories</option>' +
      '    <option>Corporate</option><option>Banking</option><option>Government</option>' +
      "  </select></div>" +
      '  <div class="table-scroll" style="margin-top:14px;"><table><thead>' +
      '    <tr><th>Domain</th><th>Category</th><th>Critical</th><th>Subdomain rules</th><th>Notes</th><th></th></tr>' +
      '  </thead><tbody id="dom-rows"></tbody></table></div></div>';

    document.getElementById("dom-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var body = {
        domain: document.getElementById("dom-domain").value.trim(),
        category: document.getElementById("dom-category").value.trim() || "Corporate",
        is_critical: document.getElementById("dom-critical").checked,
        allowed_subdomains: document.getElementById("dom-allowed").value.trim(),
        notes: document.getElementById("dom-notes").value.trim(),
      };
      var id = editingDomain;
      var p = id ? API.updateDomain(id, body) : API.createDomain(body);
      p.then(function () {
        UI.toast(id ? "Domain updated" : "Domain added", "ok");
        editingDomain = null;
        document.getElementById("dom-form").reset();
        var btn = document.getElementById("dom-form").querySelector("[type=submit]");
        btn.textContent = "Add domain";
        loadDomainsRows();
      }).catch(function (err) { UI.toast(err.message, "err"); });
    });

    document.getElementById("dom-export").addEventListener("click", function () {
      API.exportDomains().then(function (csv) {
        var blob = new Blob([csv], { type: "text/csv" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "trusted_domains.csv";
        a.click();
        URL.revokeObjectURL(a.href);
      });
    });

    document.getElementById("dom-file").addEventListener("change", function (ev) {
      var f = ev.target.files[0];
      if (!f) return;
      API.importDomains(f).then(function (res) {
        UI.toast("Imported " + res.added + ", skipped " + res.skipped, "ok");
        loadDomainsRows();
      }).catch(function (err) { UI.toast(err.message, "err"); });
      ev.target.value = "";
    });

    document.getElementById("dom-cat-filter").addEventListener("change", function (ev) {
      loadDomainsRows(ev.target.value);
    });

    loadDomainsRows();
  }

  function loadDomainsRows(category) {
    var tbody = document.getElementById("dom-rows");
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="empty"><span class="spin"></span></td></tr>';
    API.listDomains(category).then(function (rows) {
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No trusted domains yet.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (d) {
        return "<tr>" +
          "<td><span class=\"mono\">" + UI.esc(d.domain) + "</span><br>" +
          '<span class="small muted">' + UI.esc(d.normalized_domain) + "</span></td>" +
          "<td>" + UI.esc(d.category) + "</td>" +
          '<td>' + (d.is_critical ? '<span class="text-mal">critical</span>' : '<span class="muted">—</span>') + "</td>" +
          '<td class="small mono">' + UI.esc(d.allowed_subdomains || "—") + "</td>" +
          '<td class="small">' + UI.esc((d.notes || "").slice(0, 50)) + "</td>" +
          '<td class="row" style="gap:6px;flex-wrap:nowrap;">' +
          '<button class="btn btn-sm btn-ghost" data-edit="' + d.id + '">Edit</button>' +
          '<button class="btn btn-sm btn-danger" data-del="' + d.id + '">Delete</button></td></tr>';
      }).join("");
      tbody.querySelectorAll("[data-edit]").forEach(function (btn) {
        btn.addEventListener("click", function () { editDomain(Number(btn.getAttribute("data-edit"))); });
      });
      tbody.querySelectorAll("[data-del]").forEach(function (btn) {
        btn.addEventListener("click", function () { delDomain(Number(btn.getAttribute("data-del"))); });
      });
    }).catch(function (err) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">' + UI.esc(err.message) + "</td></tr>";
    });
  }

  function editDomain(id) {
    API.listDomains().then(function (rows) {
      var d = rows.filter(function (x) { return x.id === id; })[0];
      if (!d) return;
      document.getElementById("dom-domain").value = d.domain;
      document.getElementById("dom-category").value = d.category;
      document.getElementById("dom-critical").checked = d.is_critical;
      document.getElementById("dom-allowed").value = d.allowed_subdomains;
      document.getElementById("dom-notes").value = d.notes;
      window.scrollTo({ top: 0, behavior: "smooth" });
      var btn = document.getElementById("dom-form").querySelector("[type=submit]");
      btn.textContent = "Save changes";
      editingDomain = id;
      UI.toast("Click “Save changes” to apply the edit", "ok");
    });
  }

  function delDomain(id) {
    if (!window.confirm("Delete this trusted domain permanently?")) return;
    API.deleteDomain(id).then(function () {
      UI.toast("Domain deleted", "ok");
      loadDomainsRows(document.getElementById("dom-cat-filter").value);
    }).catch(function (err) { UI.toast(err.message, "err"); });
  }

  /* ===================== Blocked sites ===================== */
  var POLICY_CATEGORIES = [
    ["GAMBLING", "Gambling / betting"],
    ["ADULT", "Adult content"],
    ["SOCIAL_MEDIA", "Social media"],
    ["OTHER", "Other blocked content"],
  ];

  function policyLabel(cat) {
    if (!cat) return "Malware (always blocked)";
    for (var i = 0; i < POLICY_CATEGORIES.length; i++) {
      if (POLICY_CATEGORIES[i][0] === cat) return POLICY_CATEGORIES[i][1];
    }
    return cat;
  }

  function renderBlocked(view) {
    var cats = POLICY_CATEGORIES.map(function (c) {
      return "<option value=\"" + c[0] + "\">" + UI.esc(c[1]) + "</option>";
    }).join("");
    var filterOpts = '<option value="">All categories</option>' +
      POLICY_CATEGORIES.map(function (c) {
        return "<option value=\"" + c[0] + "\">" + UI.esc(c[1]) + "</option>";
      }).join("") + '<option value="MALWARE">Malware (uncategorized)</option>';
    view.innerHTML =
      '<div class="card"><div class="head-row"><h2>Content policy</h2></div>' +
      '<p class="sub">Sites added under these categories are blocked org-wide while the ' +
      "category is enabled. Entries without a category are always treated as malware.</p>" +
      '<div id="policy-checks" style="margin-top:10px;"></div>' +
      '<button class="btn-primary" id="policy-save" style="margin-top:12px;">Save policy</button></div>' +
      '<div class="card" style="margin-top:22px;">' +
      '  <div class="head-row"><h2>Add a blocked site</h2></div>' +
      '  <form id="blk-form"><div class="grid-3">' +
      '    <div><label>Domain</label><input type="text" id="blk-domain" required placeholder="example.com"></div>' +
      '    <div><label>Category</label><select id="blk-category">' +
      '      <option value="">Malware (always blocked)</option>' + cats + "</select></div>" +
      '    <div><label>Note</label><input type="text" id="blk-note" maxlength="2000"></div></div>' +
      '  <div class="row" style="margin-top:14px;">' +
      '    <button type="submit" class="btn-primary">Add site</button>' +
      '    <label class="small muted" style="margin:0;display:inline-flex;align-items:center;gap:6px;">' +
      '      <input type="file" id="blk-file" accept=".csv" style="width:auto;">Import CSV</label></div>' +
      "  </form></div>" +
      '<div class="card" style="margin-top:22px;"><div class="head-row"><h2>Blocked sites</h2>' +
      '<select id="blk-cat-filter" style="width:auto;margin-left:auto;">' + filterOpts + "</select></div>" +
      '<div class="table-scroll" style="margin-top:14px;"><table><thead>' +
      '<tr><th>Domain</th><th>Category</th><th>Source</th><th>Note</th><th>Added</th><th></th></tr>' +
      '</thead><tbody id="blk-rows"></tbody></table></div></div>';

    document.getElementById("blk-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var body = {
        domain: document.getElementById("blk-domain").value.trim(),
        category: document.getElementById("blk-category").value,
        note: document.getElementById("blk-note").value.trim(),
      };
      API.createBlockedSite(body).then(function () {
        UI.toast("Site blocked", "ok");
        document.getElementById("blk-form").reset();
        loadBlockedRows(document.getElementById("blk-cat-filter").value);
      }).catch(function (err) { UI.toast(err.message, "err"); });
    });

    document.getElementById("blk-file").addEventListener("change", function (ev) {
      var f = ev.target.files[0];
      if (!f) return;
      API.importBlockedSites(f).then(function (res) {
        UI.toast("Imported " + res.added + ", skipped " + res.skipped, "ok");
        if (res.errors && res.errors.length) {
          UI.toast(res.errors.slice(0, 3).join(" | "), "err");
        }
        loadBlockedRows(document.getElementById("blk-cat-filter").value);
      }).catch(function (err) { UI.toast(err.message, "err"); });
      ev.target.value = "";
    });

    document.getElementById("blk-cat-filter").addEventListener("change", function (ev) {
      loadBlockedRows(ev.target.value);
    });

    loadPolicy();
    loadBlockedRows();
  }

  function loadPolicy() {
    var box = document.getElementById("policy-checks");
    API.getContentPolicy().then(function (active) {
      box.innerHTML = POLICY_CATEGORIES.map(function (c) {
        var on = active.indexOf(c[0]) !== -1;
        return '<label style="display:inline-flex;align-items:center;gap:8px;margin-right:18px;">' +
          '<input type="checkbox" value="' + c[0] + '"' + (on ? " checked" : "") + ">" +
          UI.esc(c[1]) + "</label>";
      }).join("");
      var save = document.getElementById("policy-save");
      save.onclick = function () {
        save.disabled = true;
        var selected = Array.prototype.filter.call(
          box.querySelectorAll("input[type=checkbox]:checked"),
          function (i) { return i.value; }
        ).map(function (i) { return i.value; });
        API.updateContentPolicy(selected).then(function () {
          UI.toast("Content policy saved", "ok");
        }).catch(function (err) { UI.toast(err.message, "err"); })
          .finally(function () { save.disabled = false; });
      };
    }).catch(function (err) {
      box.innerHTML = '<span class="empty">' + UI.esc(err.message) + "</span>";
    });
  }

  function loadBlockedRows(category) {
    var tbody = document.getElementById("blk-rows");
    if (!tbody) return;
    var q = (category && category !== "MALWARE") ? category : "";
    tbody.innerHTML = '<tr><td colspan="6" class="empty"><span class="spin"></span></td></tr>';
    API.listBlockedSites(q).then(function (rows) {
      if (category === "MALWARE") { rows = rows.filter(function (r2) { return !r2.category; }); }
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No blocked sites yet.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (s) {
        return "<tr>" +
          '<td class="mono">' + UI.esc(s.domain) + "</td>" +
          "<td>" + UI.esc(policyLabel(s.category)) + "</td>" +
          "<td><span class=\"type-badge\">" + UI.esc(s.source) + "</span></td>" +
          '<td class="small">' + UI.esc((s.note || "").slice(0, 45)) + "</td>" +
          '<td class="small muted">' + UI.fmtDate(s.created_at) + "</td>" +
          '<td class="row" style="gap:6px;flex-wrap:nowrap;">' +
          '<button class="btn btn-sm btn-ghost" data-edit="' + s.id + '">Edit</button>' +
          '<button class="btn btn-sm btn-danger" data-del="' + s.id + '">Delete</button></td></tr>';
      }).join("");
      tbody.querySelectorAll("[data-edit]").forEach(function (btn) {
        btn.addEventListener("click", function () { editBlockedSite(Number(btn.getAttribute("data-edit"))); });
      });
      tbody.querySelectorAll("[data-del]").forEach(function (btn) {
        btn.addEventListener("click", function () { delBlockedSite(Number(btn.getAttribute("data-del"))); });
      });
    }).catch(function (err) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">' + UI.esc(err.message) + "</td></tr>";
    });
  }

  function editBlockedSite(id) {
    API.listBlockedSites().then(function (rows) {
      var s = rows.filter(function (x) { return x.id === id; })[0];
      if (!s) return;
      var hint = 'Keep the category (blank = malware)';
      var cat = window.prompt(hint, s.category || "");
      if (cat == null) return;
      var note = window.prompt("Note", s.note || "");
      if (note == null) note = s.note || "";
      API.updateBlockedSite(id, { domain: s.domain, category: cat.trim(), note: note.trim() })
        .then(function () {
          UI.toast("Blocked site updated", "ok");
          loadBlockedRows(document.getElementById("blk-cat-filter").value);
        }).catch(function (err) { UI.toast(err.message, "err"); });
    });
  }

  function delBlockedSite(id) {
    if (!window.confirm("Unblock this site permanently?")) return;
    API.deleteBlockedSite(id).then(function () {
      UI.toast("Site unblocked", "ok");
      loadBlockedRows(document.getElementById("blk-cat-filter").value);
    }).catch(function (err) { UI.toast(err.message, "err"); });
  }

  /* ===================== Audit ===================== */
  function renderAudit(view) {
    API.auditActions().then(function (actions) {
      var opts = '<option value="">All actions</option>' +
        actions.map(function (a) { return "<option>" + UI.esc(a) + "</option>"; }).join("");
      view.innerHTML =
        '<div class="card"><div class="head-row"><h2>Audit log</h2></div>' +
        '<div class="filter-bar" style="margin-top:10px;">' +
        '<select id="audit-action" style="width:auto;">' + opts + "</select>" +
        '<input type="text" id="audit-actor" placeholder="Actor email (substring)" style="width:auto;">' +
        '<button class="btn" id="audit-apply">Refresh</button></div>' +
        '<div class="table-scroll" style="margin-top:14px;"><table><thead>' +
        '<tr><th>Time</th><th>Action</th><th>Actor</th><th>Entity</th><th>Details</th><th>IP</th><th>Result</th></tr>' +
        "</thead><tbody id=\"audit-rows\"></tbody></table></div></div>";
      document.getElementById("audit-apply").addEventListener("click", loadAuditRows);
      document.getElementById("audit-action").addEventListener("change", loadAuditRows);
      loadAuditRows();
    }).catch(function (err) {
      view.innerHTML = '<div class="card"><div class="empty">' + UI.esc(err.message) + "</div></div>";
    });
  }

  function loadAuditRows() {
    var tbody = document.getElementById("audit-rows");
    if (!tbody) return;
    var params = {
      action: document.getElementById("audit-action").value,
      actor: document.getElementById("audit-actor").value.trim(),
      limit: 100,
    };
    tbody.innerHTML = '<tr><td colspan="7" class="empty"><span class="spin"></span></td></tr>';
    API.listAudit(params).then(function (rows) {
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No matching audit entries.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (r) {
        var detail;
        if (r.action === "SCAN_URL" && r.new) {
          detail = UI.esc((r.new.url || "").slice(0, 55)) + " → " +
            UI.esc(r.new.classification || "") + " / " + r.new.risk_score;
        } else if (r.action === "ANALYZE_EMAIL" && r.new) {
          detail = "sender " + UI.esc(r.new.sender_domain || "") + " → " + UI.esc(r.new.classification || "");
        } else if (r.action === "AUTH_FAILED") {
          detail = "failed sign-in";
        } else {
          var p = JSON.stringify(r.prev || {});
          var n = JSON.stringify(r.new || {});
          detail = UI.esc((p !== "{}" && p !== "null" ? "prev " + p.slice(0, 60) + " " : "") +
            (n !== "{}" && n !== "null" ? "new " + n.slice(0, 60) : "")).replace(/,/g, ", ");
        }
        return "<tr>" +
          '<td class="small muted">' + UI.fmtDate(r.created_at) + "</td>" +
          '<td><code>' + UI.esc(r.action) + "</code></td>" +
          '<td class="small">' + UI.esc(r.actor_email || "anonymous") + "</td>" +
          '<td class="small mono">' + UI.esc(r.entity || "—") + (r.entity_id != null ? " #" + r.entity_id : "") + "</td>" +
          '<td class="small">' + detail + "</td>" +
          '<td class="small mono">' + UI.esc(r.ip || "—") + "</td>" +
          '<td>' + (r.result === "FAIL" ? '<span class="text-mal">FAIL</span>' : '<span class="text-safe">OK</span>') + "</td></tr>";
      }).join("");
    }).catch(function (err) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">' + UI.esc(err.message) + "</td></tr>";
    });
  }

  /* ===================== Users ===================== */
  var ROLES = ["EMPLOYEE", "SECURITY_ANALYST", "ADMIN", "SUPER_ADMIN"];

  function renderUsers(view) {
    view.innerHTML =
      '<div class="card"><div class="head-row"><h2>Create user</h2></div>' +
      '<form id="user-form"><div class="grid-2">' +
      '<div><label>Email</label><input type="email" id="u-email" required placeholder="name@company-example.com"></div>' +
      '<div><label>Full name</label><input type="text" id="u-name" maxlength="120"></div>' +
      "</div>" +
      '<div class="grid-2">' +
      '<div><label>Role</label><select id="u-role">' + ROLES.map(function (r) { return "<option>" + r + "</option>"; }).join("") + "</select></div>" +
      '<div><label>Initial password (min 10 chars)</label><input type="password" id="u-pass" required minlength="10"></div>' +
      "</div>" +
      '<button type="submit" class="btn-primary" style="margin-top:14px;">Create user</button></form></div>' +
      '<div class="card" style="margin-top:22px;"><div class="head-row"><h2>Users</h2></div>' +
      '<div class="table-scroll" style="margin-top:14px;"><table><thead>' +
      '<tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th>Actions</th></tr>' +
      "</thead><tbody id=\"user-rows\"></tbody></table></div></div>";

    document.getElementById("user-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var body = {
        email: document.getElementById("u-email").value.trim(),
        full_name: document.getElementById("u-name").value.trim(),
        role: document.getElementById("u-role").value,
        password: document.getElementById("u-pass").value,
        status: "ACTIVE",
      };
      API.createUser(body).then(function () {
        UI.toast("User created", "ok");
        document.getElementById("user-form").reset();
        loadUserRows();
      }).catch(function (err) { UI.toast(err.message, "err"); });
    });

    loadUserRows();
  }

  function loadUserRows() {
    var tbody = document.getElementById("user-rows");
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" class="empty"><span class="spin"></span></td></tr>';
    API.listUsers().then(function (rows) {
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No users.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (u) {
        var self = me && u.email === me.email;
        var statusTxt = u.status === "ACTIVE" ? "text-safe" : "text-mal";
        return "<tr>" +
          "<td>" + UI.esc(u.full_name || "—") + (self ? ' <span class="type-badge">you</span>' : "") + "</td>" +
          '<td class="mono">' + UI.esc(u.email) + "</td>" +
          '<td><span class="type-badge">' + UI.esc(u.role) + "</span></td>" +
          '<td class="' + statusTxt + '">' + UI.esc(u.status) + "</td>" +
          '<td class="small muted">' + UI.fmtDate(u.last_login_at) + "</td>" +
          '<td class="row" style="gap:6px;flex-wrap:nowrap;">' +
          '<button class="btn btn-sm btn-ghost" data-role="' + u.id + '">Role</button>' +
          '<button class="btn btn-sm btn-ghost" data-toggle="' + u.id + '" data-to="' +
            (u.status === "ACTIVE" ? "DISABLED" : "ACTIVE") + '">' +
            (u.status === "ACTIVE" ? "Disable" : "Enable") + "</button>" +
          '<button class="btn btn-sm btn-ghost" data-pass="' + u.id + '">Reset pwd</button></td></tr>';
      }).join("");
      tbody.querySelectorAll("[data-role]").forEach(function (b) {
        b.addEventListener("click", function () { changeRole(Number(b.getAttribute("data-role"))); });
      });
      tbody.querySelectorAll("[data-toggle]").forEach(function (b) {
        b.addEventListener("click", function () {
          toggleUser(Number(b.getAttribute("data-toggle")), b.getAttribute("data-to"));
        });
      });
      tbody.querySelectorAll("[data-pass]").forEach(function (b) {
        b.addEventListener("click", function () { resetPass(Number(b.getAttribute("data-pass"))); });
      });
    }).catch(function (err) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">' + UI.esc(err.message) + "</td></tr>";
    });
  }

  function changeRole(id) {
    var sel = window.prompt("New role?", "EMPLOYEE");
    if (!sel) return;
    sel = sel.trim().toUpperCase().replace(/ /g, "_");
    if (ROLES.indexOf(sel) === -1) { UI.toast("Invalid role", "err"); return; }
    API.updateUser(id, { role: sel }).then(function () {
      UI.toast("Role updated", "ok"); loadUserRows();
    }).catch(function (err) { UI.toast(err.message, "err"); });
  }
  function toggleUser(id, status) {
    API.updateUser(id, { status: status }).then(function () {
      UI.toast("Status updated", "ok"); loadUserRows();
    }).catch(function (err) { UI.toast(err.message, "err"); });
  }
  function resetPass(id) {
    var pw = window.prompt("New password (min 10 chars)?");
    if (pw == null) return;
    pw = pw.trim();
    if (pw.length < 10) { UI.toast("Password too short", "err"); return; }
    API.updateUser(id, { password: pw }).then(function () {
      UI.toast("Password reset", "ok"); loadUserRows();
    }).catch(function (err) { UI.toast(err.message, "err"); });
  }

  /* ===================== Settings ===================== */
  function renderSettings(view) {
    // Load thresholds and whitelist-only in parallel
    Promise.all([API.getThresholds(), API.getWhitelistOnly().catch(function () { return { enabled: false }; })])
      .then(function (res) {
        var t = res[0], w = res[1];
        var wlChecked = w.enabled ? " checked" : "";
        view.innerHTML =
          '<div class="card"><div class="head-row"><h2>Risk score thresholds</h2></div>' +
          '<p class="sub">Scores above HIGH are MALICIOUS, above MODERATE are SUSPICIOUS; must satisfy low &lt; moderate &lt; high.</p>' +
          '<div class="grid-3">' +
          '<div><label>Low</label><input type="number" id="t-low" min="0" max="49" value="' + t.low + '"></div>' +
          '<div><label>Moderate</label><input type="number" id="t-moderate" min="1" max="74" value="' + t.moderate + '"></div>' +
          '<div><label>High</label><input type="number" id="t-high" min="2" max="99" value="' + t.high + '"></div>' +
          "</div>" +
          '<button class="btn-primary" id="t-save" style="margin-top:14px;">Save thresholds</button></div>' +
          '<div class="card" style="margin-top:22px;"><div class="head-row"><h2>Whitelist-only mode</h2></div>' +
          '<p class="sub">When enabled, <strong>every site not in your Trusted domains list is blocked</strong> — even google.com. Only domains you explicitly allow can be visited. Use this for lockdown / kiosk / exam environments.</p>' +
          '<label style="display:flex; align-items:center; gap:10px; margin-top:12px; cursor:pointer;">' +
          '<input type="checkbox" id="wl-toggle"' + wlChecked + ' style="width:18px; height:18px;">' +
          '<span><strong>Block all sites except Trusted domains</strong> — whitelist-only</span></label>' +
          '<div id="wl-warn" class="hidden" style="margin-top:10px; padding:10px; background:#3a1a1a; border:1px solid #6b2f2f; border-radius:8px; color:#ffb9b9; font-size:13px;">⚠️ When this is ON, users will only be able to visit sites you have added to <a href="#" id="wl-go-trusted" style="color:#ffb9b9; text-decoration:underline;">Trusted domains</a>. Make sure google.com, your LMS, etc. are in the allow-list before enabling.</div>' +
          '<button class="btn-primary" id="wl-save" style="margin-top:12px;">Save whitelist setting</button></div>' +
          '<div class="card danger-zone" style="margin-top:22px;"><h2>Danger zone</h2>' +
          '<p class="sub">Changing thresholds or enabling whitelist-only affects every user immediately.</p></div>';
        // Warnings
        function updateWarn() {
          var on = document.getElementById("wl-toggle").checked;
          var w2 = document.getElementById("wl-warn");
          if (w2) w2.classList.toggle("hidden", !on);
        }
        document.getElementById("wl-toggle").addEventListener("change", updateWarn);
        updateWarn();
        var goTrusted = document.getElementById("wl-go-trusted");
        if (goTrusted) goTrusted.addEventListener("click", function (e) { e.preventDefault(); document.querySelector('[data-tab="domains"]').click(); });
        document.getElementById("t-save").addEventListener("click", function () {
          var body = {
            low: Number(document.getElementById("t-low").value),
            moderate: Number(document.getElementById("t-moderate").value),
            high: Number(document.getElementById("t-high").value),
          };
          API.updateThresholds(body).then(function () {
            UI.toast("Thresholds saved", "ok");
          }).catch(function (err) { UI.toast(err.message, "err"); });
        });
        document.getElementById("wl-save").addEventListener("click", function () {
          var enabled = document.getElementById("wl-toggle").checked;
          if (enabled && !confirm("Enable whitelist-only? EVERY site not in Trusted domains will be blocked — including search engines. Continue?")) return;
          API.updateWhitelistOnly(enabled).then(function () {
            UI.toast(enabled ? "Whitelist-only ENABLED — only Trusted domains are now allowed." : "Whitelist-only disabled.", enabled ? "err" : "ok");
          }).catch(function (err) { UI.toast(err.message, "err"); });
        });
      }).catch(function (err) {
        view.innerHTML = '<div class="card"><div class="empty">' + UI.esc(err.message) + "</div></div>";
      });
  }
})();