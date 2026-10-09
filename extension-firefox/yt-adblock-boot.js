// BOTIMPHISHGUARD — injects the page-context YouTube ad-prune script.
// Firefox MV2 has no "world": "MAIN" content script, so we load the file as a
// page script. It patches fetch/XHR/JSON.parse in the page's own context.
(function () {
  "use strict";
  try {
    var NS = (typeof browser !== "undefined" && browser) ? browser : chrome;
    var s = document.createElement("script");
    s.src = NS.runtime.getURL("yt-adblock-main.js");
    s.async = false;
    s.onload = function () { try { s.remove(); } catch (e) {} };
    (document.head || document.documentElement).appendChild(s);
  } catch (e) {}
})();
