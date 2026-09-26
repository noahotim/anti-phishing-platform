// BOTIMPHISHGUARD — YouTube download buttons (video + audio)
// Injects "Download Video" and "Download Audio" below the YouTube player.
(function(){
  "use strict";
  const BTN_STYLE = "background:#1a5c2a;color:#fff;border:0;border-radius:8px;padding:8px 14px;margin-right:8px;font:600 13px system-ui;cursor:pointer;";
  const AUDIO_STYLE = "background:#1d3a55;color:#cfe0f3;border:1px solid #2f6b8f;border-radius:8px;padding:8px 14px;font:600 13px system-ui;cursor:pointer;";
  let injected = false;
  function getVideoId(){
    try { return new URL(location.href).searchParams.get("v") || ""; } catch(e){ return ""; }
  }
  function createBar(){
    if (document.getElementById("botim-download-bar")) return;
    var container = document.querySelector("#above-the-fold #title") || document.querySelector("#container #title") || document.querySelector("ytd-watch-metadata");
    if (!container) return;
    var bar = document.createElement("div");
    bar.id = "botim-download-bar";
    bar.style.cssText = "display:flex;gap:8px;margin:10px 0;flex-wrap:wrap;align-items:center;";
    var vBtn = document.createElement("button");
    vBtn.textContent = "⬇ Download Video";
    vBtn.style.cssText = BTN_STYLE;
    vBtn.title = "Download this YouTube video via BOTIMPHISHGUARD";
    vBtn.addEventListener("click", function(){
      var vid = getVideoId();
      var url = location.href;
      var dl = "https://phishguard-8vri.onrender.com/app/youtube-download.html?url=" + encodeURIComponent(url) + "&format=mp4&vid=" + encodeURIComponent(vid);
      window.open(dl, "_blank");
    });
    var aBtn = document.createElement("button");
    aBtn.textContent = "♫ Download Audio";
    aBtn.style.cssText = AUDIO_STYLE;
    aBtn.title = "Download audio (mp3) from this video";
    aBtn.addEventListener("click", function(){
      var vid = getVideoId();
      var url = location.href;
      var dl = "https://phishguard-8vri.onrender.com/app/youtube-download.html?url=" + encodeURIComponent(url) + "&format=mp3&vid=" + encodeURIComponent(vid);
      window.open(dl, "_blank");
    });
    var label = document.createElement("span");
    label.textContent = "BOTIMPHISHGUARD:";
    label.style.cssText = "font:700 12px system-ui;color:#8aa4c2;margin-right:4px;";
    bar.appendChild(label);
    bar.appendChild(vBtn);
    bar.appendChild(aBtn);
    // insert after title
    if (container.parentNode) container.parentNode.insertBefore(bar, container.nextSibling);
    else container.appendChild(bar);
    injected = true;
  }
  // YouTube is SPA — observe for navigation
  var obs = new MutationObserver(function(){ 
    if (location.pathname === "/watch") createBar();
    else { var b=document.getElementById("botim-download-bar"); if(b) b.remove(); injected=false; }
  });
  try { obs.observe(document.body, {childList:true, subtree:true}); } catch(e){}
  setInterval(function(){ if (location.pathname === "/watch" && !document.getElementById("botim-download-bar")) createBar(); }, 1500);
  // initial
  if (location.pathname === "/watch") setTimeout(createBar, 1200);
})();
