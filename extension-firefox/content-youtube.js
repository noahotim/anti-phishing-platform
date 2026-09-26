// BOTIMPHISHGUARD — YouTube ad blocker for PCs (Chrome/Edge/Brave/Opera + Firefox)
// Blocks ads but video keeps playing instantly — never hide video element.
(function () {
  "use strict";
  var SEL_SLOTS = ".ytd-ad-slot-renderer, .ytd-display-ad-renderer, #player-ads, .video-ads";
  var SEL_SKIP = ".ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button";
  // Inject CSS to hide ad overlays without touching video
  try {
    var st = document.createElement("style");
    st.textContent = ".ytp-ad-overlay-container,.ytp-ad-image-overlay{display:none!important}.ytd-ad-slot-renderer,.ytd-display-ad-renderer,#player-ads{display:none!important}";
    (document.head||document.documentElement).appendChild(st);
  } catch(e){}

  var wasAd = false;
  function tick() {
    var slots = document.querySelectorAll(SEL_SLOTS);
    for (var i = 0; i < slots.length; i++) slots[i].style.display = "none";
    // Hide ad overlay but never the video
    var adOverlay = document.querySelector(".ytp-ad-player-overlay");
    if (adOverlay) adOverlay.style.display = "none";

    var isAd = document.documentElement.classList.contains("ad-showing") ||
               !!document.querySelector(".ad-showing") ||
               !!document.querySelector(".ytp-ad-player-overlay, .ytp-ad-image-overlay");
    var btn = document.querySelector(SEL_SKIP);
    var btnVisible = btn && btn.offsetParent !== null;

    if ((isAd || btnVisible) && !wasAd) {
      try { var NS2 = (typeof browser !== "undefined" ? browser : chrome); NS2.runtime.sendMessage({type:"ad-blocked", host: location.hostname, url: location.href}); } catch(e){}
    }
    wasAd = !!(isAd || btnVisible);

    if (btnVisible) { try { btn.click(); } catch (e) {} }

    var v = document.querySelector("video.html5-main-video");
    if (v) {
      if (isAd || btnVisible) {
        try {
          // Keep video playing — mute ad, turbo through it, then resume
          v.muted = true;
          v.playbackRate = 16;
          if (v.duration && isFinite(v.duration) && v.duration > 1 && v.duration - v.currentTime > 0.1) {
            v.currentTime = Math.max(0, v.duration - 0.05);
          }
          if (v.paused) { var p = v.play(); if (p && p.catch) p.catch(function(){}); }
          else v.play().catch(function(){});
        } catch (e) {}
        if (btnVisible) setTimeout(function(){ try{ btn.click(); }catch(e){} }, 50);
      } else {
        try {
          if (v.playbackRate !== 1) v.playbackRate = 1;
          // Unmute after ad so main video has sound
          if (v.muted && !v.paused) v.muted = false;
          if (v.paused && v.readyState >= 2) { var p2=v.play(); if(p2&&p2.catch) p2.catch(function(){}); }
        } catch (e) {}
      }
    }
  }

  tick();
  var obs = new MutationObserver(function () { tick(); });
  try { obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] }); } catch (e) {}
  var raf = window.requestAnimationFrame || function(cb){ return setTimeout(cb, 16); };
  (function loop(){ tick(); raf(loop); })();
  setInterval(tick, 50);
})();
