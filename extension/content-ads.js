// BOTIMPHISHGUARD — Universal ad blocker for all sites (not only YouTube)
// Hides common ad containers, sponsored posts, and tracking iframes. Reports to live feed.
(function(){
  "use strict";
  const AD_SELECTORS = [
    "[id*='google_ads']","[class*='google-ad']","[id^='ad-']","[class^='ad-']",
    ".adsbygoogle",".ad-container",".ad-wrapper",".advertisement",".sponsored",
    "[data-ad]","[data-testid*='ad']","iframe[src*='doubleclick']","iframe[src*='googlesyndication']",
    "iframe[src*='adservice']","div[id*='ad-slot']",".ytd-ad-slot-renderer",".ytd-display-ad-renderer"
  ].join(",");
  let adCount = 0;
  let lastReport = 0;
  function hideAds(){
    try {
      var els = document.querySelectorAll(AD_SELECTORS);
      var hidden = 0;
      for (var i=0;i<els.length;i++){
        var el = els[i];
        // never hide the main video
        if (el.tagName === "VIDEO" || el.querySelector("video")) continue;
        if (el.style.display !== "none") { el.style.display = "none"; hidden++; }
      }
      if (hidden > 0) {
        adCount += hidden;
        // report once per page per 10s to avoid spam
        if (Date.now() - lastReport > 10000 && adCount > 0) {
          lastReport = Date.now();
          try {
            var NS = (typeof browser !== "undefined" ? browser : chrome);
            NS.runtime.sendMessage({type:"ad-blocked", host: location.hostname, url: location.href});
          } catch(e){}
        }
      }
    } catch(e){}
  }
  // Inject CSS for common ad classes
  try {
    var st = document.createElement("style");
    st.textContent = ".adsbygoogle,.ad-container,.advertisement,.sponsored{display:none!important} iframe[src*='doubleclick'],iframe[src*='googlesyndication']{display:none!important}";
    (document.head||document.documentElement).appendChild(st);
  } catch(e){}
  hideAds();
  var obs = new MutationObserver(hideAds);
  try { obs.observe(document.body, {childList:true, subtree:true}); } catch(e){ try{ obs.observe(document.documentElement, {childList:true, subtree:true}); }catch(e2){} }
  setInterval(hideAds, 2000);
  // also hide on scroll
  window.addEventListener("scroll", hideAds, {passive:true});
})();
