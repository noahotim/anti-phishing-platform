// BOTIMPHISHGUARD — YouTube download buttons (video + audio)
// Injects "Download Video" and "Download Audio" below the YouTube player.
(function(){
  "use strict";
  const DEF_SERVER = "https://phishguard-8vri.onrender.com";
  const BTN_STYLE = "background:#1a5c2a;color:#fff;border:0;border-radius:8px;padding:8px 14px;margin-right:8px;font:600 13px system-ui;cursor:pointer;";
  const AUDIO_STYLE = "background:#1d3a55;color:#cfe0f3;border:1px solid #2f6b8f;border-radius:8px;padding:8px 14px;font:600 13px system-ui;cursor:pointer;";
  let injected = false;

  // The server is whatever the user configured in the extension options, so
  // downloads follow the guard instead of pointing at a fixed host.
  function withServer(fn){
    try {
      if (typeof browser !== "undefined" && browser.storage && browser.storage.local) {
        browser.storage.local.get({ server: DEF_SERVER }).then(done).catch(function(){ fn(DEF_SERVER); });
        return;
      }
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get({ server: DEF_SERVER }, done);
        return;
      }
    } catch(e){}
    fn(DEF_SERVER);
    function done(raw){
      var s = (raw && raw.server) ? String(raw.server) : DEF_SERVER;
      fn(s.replace(/\/+$/, ""));
    }
  }

  function startDownload(format, quality){
    var url = location.href;
    withServer(function(server){
      var dl = server + "/api/youtube/download?url=" + encodeURIComponent(url)
             + "&format=" + format + "&quality=" + quality;
      // Single trigger: the server answers with Content-Disposition: attachment,
      // so the browser downloads in place. A second window.open here only ever
      // produced a duplicate download or an empty tab.
      var a = document.createElement("a");
      a.href = dl; a.download = ""; a.style.display = "none";
      document.body.appendChild(a); a.click();
      setTimeout(function(){ try{ document.body.removeChild(a); }catch(e){} }, 2000);
    });
  }

  function getVideoId(){
    try { return new URL(location.href).searchParams.get("v") || ""; } catch(e){ return ""; }
  }
  function findContainer(){
    return document.querySelector("ytd-watch-metadata") ||
           document.querySelector("#above-the-fold") ||
           document.querySelector("#primary-inner") ||
           document.querySelector("#primary #title") ||
           document.querySelector("#title h1") ||
           document.querySelector("ytd-video-primary-info-renderer") ||
           document.querySelector("#info") ||
           document.querySelector("#player");
  }
  function createBar(){
    if (document.getElementById("botim-download-bar")) return;
    var container = findContainer();
    if (!container) return;
    var bar = document.createElement("div");
    bar.id = "botim-download-bar";
    bar.style.cssText = "display:flex;gap:8px;margin:12px 0;padding:10px 12px;background:#0b1a2b;border:1px solid #23455f;border-radius:8px;flex-wrap:wrap;align-items:center;z-index:9999;";
    var label = document.createElement("span");
    label.textContent = "BOTIMPHISHGUARD:";
    label.style.cssText = "font:700 12px system-ui;color:#5ede8f;margin-right:4px;";
    bar.appendChild(label);
    // Video download with quality selector
    var vBtn = document.createElement("button");
    vBtn.innerHTML = "⬇ Download Video <small style='opacity:0.7;'>▼</small>";
    vBtn.style.cssText = BTN_STYLE;
    vBtn.title = "Download this YouTube video at best quality to your device";
    var vMenu = document.createElement("div");
    vMenu.style.cssText = "display:none;position:absolute;background:#132a41;border:1px solid #23455f;border-radius:6px;padding:6px;z-index:10000;flex-direction:column;gap:4px;margin-top:4px;";
    [["Best (original)","best"],["1080p","1080"],["720p","720"],["480p","480"]].forEach(function(q){
      var o=document.createElement("button"); o.textContent=q[0]; o.style.cssText="background:#1a3a5c;color:#eaf2ff;border:0;border-radius:4px;padding:6px 10px;text-align:left;cursor:pointer;font:12px system-ui;";
      o.addEventListener("click", function(e){
        e.stopPropagation(); vMenu.style.display="none";
        startDownload("mp4", q[1]);
      });
      vMenu.appendChild(o);
    });
    var vWrap=document.createElement("div"); vWrap.style.cssText="position:relative;display:inline-block;"; vWrap.appendChild(vBtn); vWrap.appendChild(vMenu);
    vBtn.addEventListener("click", function(e){ e.stopPropagation(); vMenu.style.display = vMenu.style.display==="none"?"flex":"none"; aMenu.style.display="none"; });
    bar.appendChild(vWrap);
    // Audio download with quality selector
    var aBtn = document.createElement("button");
    aBtn.innerHTML = "♫ Download Audio <small style='opacity:0.7;'>▼</small>";
    aBtn.style.cssText = AUDIO_STYLE;
    aBtn.title = "Download audio (mp3) at best quality";
    var aMenu=document.createElement("div");
    aMenu.style.cssText="display:none;position:absolute;background:#132a41;border:1px solid #23455f;border-radius:6px;padding:6px;z-index:10000;flex-direction:column;gap:4px;margin-top:4px;";
    [["Best (320kbps)","best"],["High (192kbps)","192"],["Medium (128kbps)","128"]].forEach(function(q){
      var o=document.createElement("button"); o.textContent=q[0]; o.style.cssText="background:#1a3a5c;color:#eaf2ff;border:0;border-radius:4px;padding:6px 10px;text-align:left;cursor:pointer;font:12px system-ui;";
      o.addEventListener("click", function(e){
        e.stopPropagation(); aMenu.style.display="none";
        startDownload("mp3", q[1]);
      });
      aMenu.appendChild(o);
    });
    var aWrap=document.createElement("div"); aWrap.style.cssText="position:relative;display:inline-block;"; aWrap.appendChild(aBtn); aWrap.appendChild(aMenu);
    aBtn.addEventListener("click", function(e){ e.stopPropagation(); aMenu.style.display = aMenu.style.display==="none"?"flex":"none"; vMenu.style.display="none"; });
    bar.appendChild(aWrap);
    document.addEventListener("click", function(){ vMenu.style.display="none"; aMenu.style.display="none"; });
    // Insert below video info
    var anchor = document.querySelector("ytd-watch-metadata") || document.querySelector("#above-the-fold") || container;
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(bar, anchor.nextSibling);
    else if (container.parentNode) container.parentNode.insertBefore(bar, container.nextSibling);
    else document.body.appendChild(bar);
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
