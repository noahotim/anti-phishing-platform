/* Feedback page */
(function () {
  "use strict";

  function loadPublic() {
    fetch("/api/feedback/public")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var list = document.getElementById("fb-list");
        if (!data.feedback || !data.feedback.length) {
          list.innerHTML = '<span class="muted">No feedback yet — be the first!</span>';
          return;
        }
        list.innerHTML = data.feedback.map(function (f) {
          var stars = f.rating ? "★".repeat(f.rating) + "☆".repeat(5 - f.rating) : "";
          return '<div style="padding:10px 0; border-bottom:1px solid #1e3a52;">' +
            '<div><strong>' + UI.esc(f.name || "Anonymous") + '</strong> ' +
            (stars ? '<span style="color:#ffb454;">' + stars + '</span> ' : '') +
            '<span class="muted" style="font-size:12px;">' + UI.esc(f.category) + ' · ' + UI.fmtDate(f.created_at) + '</span></div>' +
            '<div style="margin-top:4px;">' + UI.esc(f.message) + '</div></div>';
        }).join("");
      })
      .catch(function () {
        document.getElementById("fb-list").textContent = "Could not load feedback.";
      });
  }

  function loadGform(user) {
    fetch("/api/feedback/gform")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var url = data.url || "";
        var frame = document.getElementById("gform-frame");
        var ph = document.getElementById("gform-placeholder");
        var input = document.getElementById("gform-url");
        if (url) {
          frame.src = url;
          frame.style.display = "";
          ph.style.display = "none";
          if (input) input.value = url;
        }
        // Show admin box only to admins
        var isAdmin = user && (user.role === "ADMIN" || user.role === "SUPER_ADMIN");
        var adminBox = document.getElementById("gform-admin");
        if (adminBox) {
          if (isAdmin) adminBox.classList.remove("hidden");
          else adminBox.classList.add("hidden");
        }
      }).catch(function () {});
  }

  document.addEventListener("DOMContentLoaded", function () {
    UI.boot().then(function (user) { loadPublic(); loadGform(user); });

    var form = document.getElementById("fb-form");
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var msg = document.getElementById("fb-msg");
      var btn = document.getElementById("fb-submit");
      var payload = {
        name: document.getElementById("fb-name").value,
        email: document.getElementById("fb-email").value,
        rating: parseInt(document.getElementById("fb-rating").value, 10) || 0,
        category: document.getElementById("fb-category").value,
        message: document.getElementById("fb-message").value,
        browser: navigator.userAgent.slice(0, 200),
        url: window.location.href
      };
      if (!payload.message || payload.message.trim().length < 3) {
        UI.toast("Please write a message.", "err");
        return;
      }
      btn.disabled = true;
      msg.textContent = "Sending…";
      fetch("/api/feedback", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload)
      }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      }).then(function () {
        UI.toast("Thanks for your feedback!", "ok");
        msg.textContent = "Sent — thank you!";
        form.reset();
        loadPublic();
      }).catch(function (err) {
        UI.toast("Could not send: " + err.message, "err");
        msg.textContent = "Failed: " + err.message;
      }).then(function () { btn.disabled = false; });
    });

    var gSave = document.getElementById("gform-save");
    if (gSave) {
      gSave.addEventListener("click", function () {
        var url = document.getElementById("gform-url").value.trim();
        var m2 = document.getElementById("gform-msg");
        if (!url) { m2.textContent = "Paste a Google Forms embed URL."; return; }
        if (url.indexOf("docs.google.com/forms") === -1) { m2.textContent = "Must be a docs.google.com/forms URL."; return; }
        m2.textContent = "Saving…";
        gSave.disabled = true;
        var token = (window.API && API.getToken) ? API.getToken() : (localStorage.getItem("phishguard_token") || "");
        fetch("/api/feedback/gform", {
          method: "PUT",
          headers: { "content-type": "application/json", "Authorization": token ? "Bearer " + token : "" },
          body: JSON.stringify({ url: url })
        }).then(function (r) {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        }).then(function () {
          m2.textContent = "Saved — reloading…";
          var frame = document.getElementById("gform-frame");
          var ph = document.getElementById("gform-placeholder");
          frame.src = url;
          frame.style.display = "";
          ph.style.display = "none";
          UI.toast("Google Form embedded in the guard.", "ok");
        }).catch(function (e) {
          m2.textContent = "Failed: " + e.message;
          UI.toast("Could not save: " + e.message, "err");
        }).then(function () { gSave.disabled = false; });
      });
    }
  });
})();
