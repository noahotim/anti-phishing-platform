/* Shared UI helpers: topbar, toast, escaping, badges. */
(function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function escAttr(s) { return esc(s); }

  function badgeFor(cls) {
    if (cls === "SAFE") return '<span class="bdg-safe">SAFE</span>';
    if (cls === "SUSPICIOUS") return '<span class="bdg-susp">SUSPICIOUS</span>';
    if (cls === "MALICIOUS") return '<span class="bdg-mal">MALICIOUS</span>';
    return '<span class="bdg-unk">UNKNOWN</span>';
  }

  function toast(msg, kind) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.className = "show" + (kind ? " " + kind : "");
    clearTimeout(el._t);
    el._t = setTimeout(function () { el.className = ""; }, 4200);
  }

  function fmtDate(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d)) return esc(iso);
    return d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  }

  function shortDate(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d)) return esc(iso);
    return d.toLocaleDateString(undefined, { month: "short", day: "2-digit" });
  }

  var ROLE_HINT = {
    EMPLOYEE: "Employee",
    SECURITY_ANALYST: "Analyst",
    ADMIN: "Admin",
    SUPER_ADMIN: "Super Admin",
  };

  /* Resolve who we are and render the shared topbar. Returns a Promise of the
     user object or null when anonymous. */
  function boot(required) {
    var bar = document.querySelector("[data-topbar]");
    return Promise.resolve()
      .then(function () { return API.me(); })
      .catch(function () { return null; })
      .then(function (user) {
        if (bar) renderTopbar(bar, user);
        if (user) bindLogout();
        if (required && !user) {
          window.location.href = "/app/login.html";
          throw new Error("authentication required");
        }
        if (required && required.indexOf(user.role) === -1) {
          window.location.href = "/app/index.html";
          throw new Error("insufficient permissions");
        }
        return user;
      });
  }

  function renderTopbar(bar, user) {
    var role = user ? (ROLE_HINT[user.role] || user.role) : "";
    bar.innerHTML =
      '<a class="brand" href="/app/index.html">' +
      '  <span class="logo">PG</span><span class="gradient-text">PhishGuard</span>' +
      "</a>" +
      '<span class="spacer"></span>' +
      (user ? userChip(user, role) + logoutBtn() : signInBtn());
  }

  function signInBtn() {
    return '<a class="btn btn-sm" href="/app/login.html">Sign in</a>';
  }

  function logoutBtn() {
    return '<button type="button" id="logoutBtn" class="btn btn-ghost btn-sm">Sign out</button>';
  }

  function userChip(user, role) {
    return '<span class="user-chip">' +
      '<span>Signed in as <strong>' + esc(user.full_name || user.email) + "</strong></span>" +
      '<span class="role-badge">' + esc(role) + "</span></span>";
  }

  function bindLogout() {
    var btn = document.getElementById("logoutBtn");
    if (btn) {
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        API.logout().then(function () { window.location.href = "/app/index.html"; });
      });
    }
  }

  window.UI = {
    esc: esc,
    escAttr: escAttr,
    badge: badgeFor,
    toast: toast,
    fmtDate: fmtDate,
    shortDate: shortDate,
    boot: boot,
    bindLogout: bindLogout,
  };
})();