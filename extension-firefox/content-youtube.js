// PhishGuard — YouTube ad blocker for PCs (Chrome/Edge/Brave/Opera + Firefox)
// Fixes 1.1.7 regression that hid videos: never hide .ad-showing/.ytp-ad-module.
// Only hides external slot ads; for in-player ads we click Skip and fast-forward.
(function () {
  "use strict";
  var SEL_SLOTS = ".ytd-ad-slot-renderer, .ytd-display-ad-renderer, #player-ads, .video-ads";
  var SEL_SKIP = ".ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button";

  function tick() {
    var slots = document.querySelectorAll(SEL_SLOTS);
    for (var i = 0; i < slots.length; i++) slots[i].style.display = "none";

    var isAd = document.documentElement.classList.contains("ad-showing") ||
               !!document.querySelector(".ad-showing") ||
               !!document.querySelector(".ytp-ad-player-overlay, .ytp-ad-image-overlay");
    var btn = document.querySelector(SEL_SKIP);
    var btnVisible = btn && btn.offsetParent !== null;

    if (btnVisible) { try { btn.click(); } catch (e) {} }

    var v = document.querySelector("video.html5-main-video");
    if (v) {
      if (isAd || btnVisible) {
        try {
          v.muted = true;
          v.playbackRate = 16;
          // Instantly jump to end of ad - YouTube then fires ad end -> video
          if (v.duration && isFinite(v.duration) && v.duration > 1 && v.duration - v.currentTime > 0.1) {
            v.currentTime = Math.max(0, v.duration - 0.05);
          }
          if (v.paused) { var p = v.play(); if (p && p.catch) p.catch(function(){}); }
        } catch (e) {}
        // Re-click skip on next frame for 5-sec delayed button
        if (btnVisible) setTimeout(function(){ try{ btn.click(); }catch(e){} }, 50);
      } else {
        // Back to normal video - restore speed and unmute if we muted it
        try { if (v.playbackRate !== 1) v.playbackRate = 1; } catch (e) {}
      }
    }
  }

  tick();
  var obs = new MutationObserver(function () { tick(); });
  try { obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] }); } catch (e) {}
  // 80ms poll = ~instant (was 700ms lag); rAF for first frames
  var raf = window.requestAnimationFrame || function(cb){ return setTimeout(cb, 16); };
  (function loop(){ tick(); raf(loop); })();
  setInterval(tick, 80);
})();
