// BOTIMPHISHGUARD — YouTube ad-stealth (page/MAIN world).
//
// YouTube's anti-adblock enforcement fires when the player is told there are
// ads but the ad resources fail to load. Instead of blocking requests (which
// is detectable), we remove the ad metadata from the player response *before
// YouTube's own player reads it*, so the player simply believes the video has
// no ads and never requests one. That is both ad-free and undetectable.
//
// Also blocks nothing itself and hides nothing in the DOM, so there is no
// cosmetic fingerprint. Runs at document_start, before the player boots.
(function () {
  "use strict";
  if (window.__botimYtAdPrune) return;
  window.__botimYtAdPrune = true;

  // Keys YouTube uses to describe ads in player/next responses.
  var AD_KEYS = [
    "adPlacements",
    "adSlots",
    "playerAds",
    "adParams",
    "playerAdParams",
    "adOnesie",
    "adBreakHeartbeatParams",
    "importantForAds",
  ];
  // Quick substring gate so we do no work on ordinary responses.
  var GATE = /adPlacements|adSlots|playerAds|adParams|adOnesie|adBreakHeartbeatParams/;

  function pruneObj(node, depth) {
    if (!node || typeof node !== "object" || depth > 12) return;
    if (Array.isArray(node)) {
      for (var i = 0; i < node.length; i++) pruneObj(node[i], depth + 1);
      return;
    }
    for (var k = 0; k < AD_KEYS.length; k++) {
      if (Object.prototype.hasOwnProperty.call(node, AD_KEYS[k])) {
        try { delete node[AD_KEYS[k]]; } catch (e) { node[AD_KEYS[k]] = Array.isArray(node[AD_KEYS[k]]) ? [] : undefined; }
      }
    }
    for (var key in node) {
      if (!Object.prototype.hasOwnProperty.call(node, key)) continue;
      var v = node[key];
      if (v && typeof v === "object") pruneObj(v, depth + 1);
    }
  }

  // Remove a JSON value that follows `"key":` in a raw text blob (JSON or an
  // HTML page with embedded JSON), replacing it with []. Used for the initial
  // watch-page HTML, whose player response is not created via JSON.parse.
  function scanValueEnd(s, i) {
    var n = s.length;
    while (i < n && /\s/.test(s[i])) i++;
    var c = s[i];
    if (c === '"') {
      i++;
      while (i < n) {
        if (s[i] === "\\") { i += 2; continue; }
        if (s[i] === '"') return i + 1;
        i++;
      }
      return -1;
    }
    if (c === "{" || c === "[") {
      var open = c, close = c === "{" ? "}" : "]";
      var depth = 0, inStr = false, esc = false;
      for (; i < n; i++) {
        var ch = s[i];
        if (inStr) {
          if (esc) { esc = false; }
          else if (ch === "\\") { esc = true; }
          else if (ch === '"') { inStr = false; }
          continue;
        }
        if (ch === '"') { inStr = true; continue; }
        if (ch === open) depth++;
        else if (ch === close) { depth--; if (depth === 0) return i + 1; }
      }
      return -1;
    }
    // number / true / false / null
    var j = i;
    while (j < n && !/[,}\]]/.test(s[j])) j++;
    return j;
  }

  function stripKeyFromText(text, key) {
    var needle = '"' + key + '"';
    var out = text, from = 0;
    for (;;) {
      var at = out.indexOf(needle, from);
      if (at < 0) return out;
      var j = at + needle.length;
      while (j < out.length && /\s/.test(out[j])) j++;
      if (out[j] !== ":") { from = at + needle.length; continue; }
      j++;
      var end = scanValueEnd(out, j);
      if (end < 0) { from = at + needle.length; continue; }
      out = out.slice(0, j) + "[]" + out.slice(end);
      from = j + 2;
    }
  }

  function pruneText(text) {
    if (typeof text !== "string" || !GATE.test(text)) return text;
    var out = text;
    for (var i = 0; i < AD_KEYS.length; i++) out = stripKeyFromText(out, AD_KEYS[i]);
    return out;
  }

  function report() {
    try { window.postMessage({ source: "botim-ytad", type: "ad-pruned" }, "*"); } catch (e) {}
  }

  function isPlayerResponse(url) {
    if (!url) return false;
    return (
      url.indexOf("/youtubei/v1/player") >= 0 ||
      url.indexOf("/youtubei/v1/next") >= 0 ||
      url.indexOf("/youtubei/v1/browse") >= 0 ||
      url.indexOf("/watch") >= 0 ||
      url.indexOf("/get_ad") >= 0 ||
      url.indexOf("/pagead/") >= 0 ||
      url.indexOf("get_midroll") >= 0
    );
  }

  // 1. fetch -----------------------------------------------------------------
  try {
    var origFetch = window.fetch;
    if (typeof origFetch === "function") {
      window.fetch = function (input, init) {
        var url = typeof input === "string" ? input : (input && input.url) || "";
        var p = origFetch.apply(this, arguments);
        if (!isPlayerResponse(url)) return p;
        return p.then(function (res) {
          try {
            return res.clone().text().then(function (text) {
              var patched = pruneText(text);
              if (patched === text) return res;
              var headers = new Headers(res.headers);
              try { headers.delete("content-length"); headers.delete("content-encoding"); } catch (e) {}
              report();
              return new Response(patched, { status: res.status, statusText: res.statusText, headers: headers });
            }).catch(function () { return res; });
          } catch (e) { return res; }
        });
      };
    }
  } catch (e) {}

  // 2. XMLHttpRequest --------------------------------------------------------
  try {
    var XO = XMLHttpRequest.prototype.open;
    var XS = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (m, u) {
      try { this.__botimUrl = u; } catch (e) {}
      return XO.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      var xhr = this;
      try {
        xhr.addEventListener("readystatechange", function () {
          if (xhr.readyState !== 4) return;
          if (!isPlayerResponse(xhr.__botimUrl || "")) return;
          try {
            var rt = xhr.responseType;
            if (rt === "" || rt === "text") {
              var text = xhr.responseText;
              var patched = pruneText(text);
              if (patched !== text) {
                Object.defineProperty(xhr, "responseText", { value: patched, configurable: true });
                Object.defineProperty(xhr, "response", { value: patched, configurable: true });
                report();
              }
            }
          } catch (e) {}
        });
      } catch (e) {}
      return XS.apply(this, arguments);
    };
  } catch (e) {}

  // 3. JSON.parse ------------------------------------------------------------
  try {
    var origParse = JSON.parse;
    JSON.parse = function () {
      var result = origParse.apply(this, arguments);
      try {
        var text = arguments[0];
        if (typeof text === "string" && GATE.test(text)) pruneObj(result, 0);
      } catch (e) {}
      return result;
    };
  } catch (e) {}

  // 4. Response.json ---------------------------------------------------------
  try {
    var origJson = Response.prototype.json;
    Response.prototype.json = function () {
      return origJson.apply(this, arguments).then(function (obj) {
        try { pruneObj(obj, 0); } catch (e) {}
        return obj;
      });
    };
  } catch (e) {}

  // 5. ytInitialPlayerResponse (initial watch pages) -------------------------
  // If present before our hook could run, prune it in place once available.
  function pruneInitial() {
    try {
      var ipr = window.ytInitialPlayerResponse;
      if (ipr && typeof ipr === "object") pruneObj(ipr, 0);
    } catch (e) {}
  }
  pruneInitial();
  try {
    var tries = 0;
    var timer = setInterval(function () {
      pruneInitial();
      if (++tries > 40) clearInterval(timer);
    }, 250);
  } catch (e) {}
})();
