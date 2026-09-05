// PhishGuard — YouTube ad blocker for PCs (Chrome/Edge/Brave/Opera + Firefox)
// Fixes 1.1.7 regression that hid videos: never hide .ad-showing/.ytp-ad-module.
// Only hides external slot ads; for in-player ads we click Skip and fast-forward.
(function () {
  "use strict";
  var SEL_SLOTS = ".ytd-ad-slot-renderer, .ytd-display-ad-renderer, #player-ads, .video-ads";
  var SEL_SKIP = ".ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button";

  function tick() {
    // Hide only feed/sidebar ad slots - never the player itself
    var slots = document.querySelectorAll(SEL_SLOTS);
    for (var i = 0; i < slots.length; i++) slots[i].style.display = "none";

    var isAd = document.documentElement.classList.contains("ad-showing") ||
               !!document.querySelector(".ad-showing");
    var btn = document.querySelector(SEL_SKIP);
    var btnVisible = btn && btn.offsetParent !== null;

    if (isAd || btnVisible) {
      if (btnVisible) { try { btn.click(); } catch (e) {} }
      var v = document.querySelector("video.html5-main-video");
      if (v && isAd) {
        try {
          v.muted = true;
          if (v.duration && isFinite(v.duration) && v.duration - v.currentTime > 0.5) {
            v.currentTime = v.duration;
          }
          if (v.paused) { var p = v.play(); if (p && p.catch) p.catch(function(){}); }
        } catch (e) {}
      }
    }
  }

  tick();
  var obs = new MutationObserver(function () { tick(); });
  try { obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true }); } catch (e) {}
  setInterval(tick, 700);
})();
