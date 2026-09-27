// BOTIMPHISHGUARD — YouTube ad blocker for PCs (Chrome/Edge/Brave/Opera + Firefox)
// Goal: zero disruption. Ads are skipped/overlaid the instant they appear and the
// main video keeps playing at normal speed with normal sound. No stalls, no lost
// seconds, no per-frame jank.
(function () {
  "use strict";

  var SEL_SKIP = ".ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-ad-skip-ad-button, .ytp-ad-skip-button-slot button";
  var SEL_AD_OUTSIDE_PLAYER = ".ytd-ad-slot-renderer, .ytd-display-ad-renderer, .ytd-in-feed-ad-layout-renderer, .ytd-promoted-sparkles-web-renderer";

  // Hide ad chrome only. `#player-ads` is kept in the layout (visibility, not
  // display:none) so YouTube still fires its ad-ended signal and the player
  // never hangs waiting for an ad that is no longer there.
  try {
    var st = document.createElement("style");
    st.id = "botim-ad-style";
    st.textContent =
      ".ytp-ad-overlay-container,.ytp-ad-image-overlay,.ytp-ad-overlay-slot," +
      ".ytp-ad-text-overlay,.ytp-ad-preview-container{display:none!important}" +
      "#player-ads{visibility:hidden!important;pointer-events:none!important}" +
      SEL_AD_OUTSIDE_PLAYER + "{display:none!important}";
    (document.head || document.documentElement).appendChild(st);
  } catch (e) {}

  var adActive = false;          // true while an ad is on screen
  var restoreMuted = false;      // the user's own mute state, captured on ad start
  var restoreRate = 1;           // the user's own playback rate, captured on ad start
  var skipTries = 0;             // how many times we have clicked Skip this ad
  var recoverTries = 0;          // playback recovery attempts for the current ad
  var lastReport = 0;            // throttle ad-blocked reports to the background

  function notifyAdBlocked() {
    var now = Date.now();
    if (now - lastReport < 30000) return;
    lastReport = now;
    try {
      var NS2 = (typeof browser !== "undefined" ? browser : chrome);
      NS2.runtime.sendMessage({ type: "ad-blocked", host: location.hostname, url: location.href });
    } catch (e) {}
  }

  function findSkip() {
    var btns = document.querySelectorAll(SEL_SKIP);
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].offsetParent !== null) return btns[i];
    }
    return null;
  }

  function adOnScreen() {
    if (document.documentElement.classList.contains("ad-showing")) return true;
    if (document.body && document.body.classList.contains("ad-showing")) return true;
    if (document.querySelector(".ad-showing")) return true;
    if (document.querySelector("#player-ads.ytp-ad-module .ytp-ad-player-overlay")) return true;
    if (document.querySelector(".ytp-ad-player-overlay, .ytp-ad-image-overlay")) return true;
    return false;
  }

  function mainVideo() {
    return document.querySelector("video.html5-main-video") ||
           document.querySelector("#movie_player video");
  }

  // Run every 100ms. Cheap: one class read plus a few selector lookups, and the
  // MutationObserver below covers DOM changes so this never needs a rAF loop.
  function tick() {
    var v = mainVideo();
    var btn = findSkip();
    var showing = adOnScreen() || !!btn;

    if (showing && !adActive) {
      // Ad just started: remember how the user likes their video, then fast-forward.
      adActive = true;
      skipTries = 0;
      recoverTries = 0;
      if (v) { restoreMuted = v.muted; restoreRate = v.playbackRate || 1; }
      notifyAdBlocked();
    } else if (!showing && adActive) {
      // Ad gone: put everything back exactly as the user had it.
      adActive = false;
      if (v) {
        try { if (v.playbackRate !== restoreRate) v.playbackRate = restoreRate; } catch (e) {}
        try { if (v.muted !== restoreMuted) v.muted = restoreMuted; } catch (e) {}
        if (v.paused && v.readyState >= 2) {
          try { var p = v.play(); if (p && p.catch) p.catch(function () {}); } catch (e) {}
        }
      }
      return;
    }

    if (!adActive) return;

    if (btn) {
      // Click Skip hard and early — that is the fastest exit, no seeking needed.
      skipTries++;
      try { btn.click(); } catch (e) {}
    }

    if (v) {
      try {
        v.muted = true;                       // ad audio off, main video untouched
        if (v.playbackRate < 16) v.playbackRate = 16;   // burn through any unskippable ad
      } catch (e) {}

      // Only seek for ads that will not let us skip. Seeking a skippable ad
      // causes YouTube to stall or replay, which is what wasted time before.
      if (!btn && v.duration && isFinite(v.duration) && v.duration > 1 &&
          v.duration - v.currentTime > 0.1 && v.currentTime < v.duration - 0.1) {
        try { v.currentTime = Math.max(0, v.duration - 0.05); } catch (e) {}
      }

      // Recover playback if the ad knocked the player into a paused state.
      if (v.paused) {
        recoverTries++;
        if (recoverTries <= 40) {
          try { var p2 = v.play(); if (p2 && p2.catch) p2.catch(function () {}); } catch (e) {}
        }
      }
    }
  }

  tick();
  try {
    new MutationObserver(tick).observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["class"]
    });
  } catch (e) {}
  setInterval(tick, 100);
})();
