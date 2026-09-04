/* Shared API client with bearer-token handling. */
(function () {
  "use strict";

  var TOKEN_KEY = "phishguard_token";

  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || "";
  }

  function setToken(t) {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  }

  async function request(method, path, body) {
    var headers = { "Content-Type": "application/json" };
    var token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    var res = await fetch(path, {
      method: method,
      headers: headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401 && path !== "/api/auth/login") {
      setToken("");
      window.location.href = "/app/login.html";
      throw new Error("session expired");
    }
    var data;
    try {
      data = await res.json();
    } catch (e) {
      data = {};
    }
    if (!res.ok) {
      var msg = data && data.detail;
      if (Array.isArray(msg)) msg = msg.map(function (m) { return m.message || m.msg; }).join("; ");
      if (data && data.errors) {
        msg = (data.errors || []).map(function (e) {
          return (e.field ? e.field + ": " : "") + e.message;
        }).join("; ") || msg;
      }
      throw new Error(msg || ("HTTP " + res.status));
    }
    return data;
  }

  function formData(path, fd) {
    var headers = {};
    var token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    return fetch(path, { method: "POST", headers: headers, body: fd }).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) throw new Error((data && data.detail) || ("HTTP " + res.status));
        return data;
      });
    });
  }

  window.API = {
    getToken: getToken,
    setToken: setToken,

    health: function () { return request("GET", "/api/health"); },

    login: function (email, password) {
      return request("POST", "/api/auth/login", { email: email, password: password });
    },
    logout: function () {
      return request("POST", "/api/auth/logout").catch(function () {}).then(function () {
        setToken("");
      });
    },
    me: function () { return request("GET", "/api/auth/me"); },

    analyzeUrl: function (url) {
      return request("POST", "/api/analyze/url", { url: url });
    },
    getScan: function (id) { return request("GET", "/api/analyze/" + id); },

    analyzeEmail: function (payload) {
      return request("POST", "/api/email/analyze", payload);
    },

    reportUrl: function (url, comment) {
      return request("POST", "/api/reports", { url: url, comment: comment });
    },
    listReports: function (status) {
      var q = status ? "?status=" + encodeURIComponent(status) : "";
      return request("GET", "/api/reports" + q);
    },
    updateReportStatus: function (id, status, comment) {
      return request("PUT", "/api/reports/" + id, { status: status, comment: comment });
    },

    dashboardStats: function (days) {
      return request("GET", "/api/dashboard/statistics?days=" + (days || 30));
    },

    listDomains: function (category) {
      var q = category ? "?category=" + encodeURIComponent(category) : "";
      return request("GET", "/api/trusted-domains" + q);
    },
    createDomain: function (body) {
      return request("POST", "/api/trusted-domains", body);
    },
    updateDomain: function (id, body) {
      return request("PUT", "/api/trusted-domains/" + id, body);
    },
    deleteDomain: function (id) {
      return request("DELETE", "/api/trusted-domains/" + id);
    },
    importDomains: function (file) {
      var fd = new FormData();
      fd.append("file", file);
      return formData("/api/trusted-domains/import", fd);
    },
    exportDomains: function () {
      var token = getToken();
      var headers = token ? { "Authorization": "Bearer " + token } : {};
      return fetch("/api/trusted-domains/export", { headers: headers }).then(function (res) {
        return res.text();
      });
    },

    listAudit: function (params) {
      var q = Object.keys(params || {}).filter(function (k) { return params[k]; })
        .map(function (k) { return k + "=" + encodeURIComponent(params[k]); })
        .join("&");
      return request("GET", "/api/audit-logs" + (q ? "?" + q : ""));
    },
    auditActions: function () { return request("GET", "/api/audit-logs/actions"); },

    listUsers: function (role) {
      var q = role ? "?role=" + encodeURIComponent(role) : "";
      return request("GET", "/api/users" + q);
    },
    createUser: function (body) { return request("POST", "/api/users", body); },
    updateUser: function (id, body) { return request("PUT", "/api/users/" + id, body); },

    getThresholds: function () { return request("GET", "/api/settings/risk-thresholds"); },
    updateThresholds: function (body) { return request("PUT", "/api/settings/risk-thresholds", body); },

    threatIntelStatus: function () { return request("GET", "/api/threat-intel"); },
    syncThreatIntel: function () { return request("POST", "/api/threat-intel/sync"); },

    listBlockedSites: function (category) {
      var q = category ? "?category=" + encodeURIComponent(category) : "";
      return request("GET", "/api/blocked-sites" + q);
    },
    createBlockedSite: function (body) {
      return request("POST", "/api/blocked-sites", body);
    },
    updateBlockedSite: function (id, body) {
      return request("PUT", "/api/blocked-sites/" + id, body);
    },
    deleteBlockedSite: function (id) {
      return request("DELETE", "/api/blocked-sites/" + id);
    },
    importBlockedSites: function (file) {
      var fd = new FormData();
      fd.append("file", file);
      return formData("/api/blocked-sites/import", fd);
    },

    getContentPolicy: function () { return request("GET", "/api/settings/content-policy"); },
    updateContentPolicy: function (categories) {
      return request("PUT", "/api/settings/content-policy", { categories: categories });
    },
    getWhitelistOnly: function () { return request("GET", "/api/settings/whitelist-only"); },
    updateWhitelistOnly: function (enabled) {
      return request("PUT", "/api/settings/whitelist-only", { enabled: enabled });
    },
  };
})();