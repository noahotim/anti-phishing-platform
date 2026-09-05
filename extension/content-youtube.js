// PhishGuard — YouTube ad blocker for PCs (Chrome/Edge/Brave/Opera + Firefox)
// Hides pre-roll/mid-roll ad UI and auto-clicks Skip when it appears.
(function () {
  "use strict";
  const SEL_AD = ".ad-showing, .ytp-ad-module, #player-ads, .video-ads, .ytd-ad-slot-renderer, .ytd-display-ad-renderer";
  const SEL_SKIP = ".ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button";

  function skipIfNeeded() {
    const btn = document.querySelector(SEL_SKIP);
    if (btn && btn.offsetParent !== null) {
      try { btn.click(); } catch (e) {}
      // Also try to jump video to end to skip unskippable
      const v = document.querySelector("video.html5-main-video");
      if (v && v.duration && isFinite(v.duration)) {
        try { v.currentTime = v.duration; } catch (e) {}
      }
    }
    // Hide ad containers
    document.querySelectorAll(SEL_AD).forEach(function (el) {
      el.style.display = "none";
    });
  }

  // Run immediately and on mutations (YouTube is SPA)
  skipIfNeeded();
  const obs = new MutationObserver(function () { skipIfNeeded(); });
  obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
  // Also poll as fallback (YouTube sometimes re-adds ads)
  setInterval(skipIfNeeded, 500);
})();
