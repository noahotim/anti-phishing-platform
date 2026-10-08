// Sets a flag so https://phishguard-8vri.onrender.com/app/install.html can detect that PhishGuard is already installed
try {
  window.phishGuardInstalled = true;
  document.documentElement.setAttribute('data-phishguard-installed', 'true');
  // Also dispatch an event for the page to listen to
  window.dispatchEvent(new CustomEvent('phishguard-installed', { detail: { installed: true } }));
} catch (e) {}

// After the user whitelists a site on this page, tell the background worker so
// it drops its cached block verdict and refreshes the rule feed immediately.
// Without this the extension keeps blocking for up to 10 minutes (verdict
// cache) or 30 minutes (rule refresh) after a successful whitelist add.
try {
  (function () {
    var api = (typeof chrome !== "undefined" && chrome.runtime) ? chrome
            : ((typeof browser !== "undefined" && browser.runtime) ? browser : null);
    function notify(host) {
      host = String(host || "").toLowerCase();
      if (!host || !api) return;
      try { api.runtime.sendMessage({ type: "whitelist-added", host: host }); } catch (e) {}
    }
    var obs = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        if (muts[i].attributeName === "data-phishguard-whitelisted") {
          notify(document.documentElement.getAttribute("data-phishguard-whitelisted"));
        }
      }
    });
    obs.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-phishguard-whitelisted"]
    });
    // Belt and braces: the page also fires a CustomEvent.
    window.addEventListener("phishguard-whitelisted", function (e) {
      try { notify(e.detail && e.detail.domain); } catch (err) {}
    });
  })();
} catch (e) {}
