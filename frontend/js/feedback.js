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

  document.addEventListener("DOMContentLoaded", function () {
    UI.boot().then(function () { loadPublic(); });

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
  });
})();
