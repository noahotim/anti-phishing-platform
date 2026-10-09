// BOTIMPHISHGUARD — Firefox client-side YouTube downloader glue.
// Loaded as a background page script after vendor/yt-download.js. Exposes
// self.BOTIM_YT.download, which the background message router calls.
(function () {
  "use strict";
  var NS = (typeof browser !== "undefined" && browser) ? browser : chrome;

  function cookieString() {
    return Promise.all([
      NS.cookies.getAll({ domain: "youtube.com" }).catch(function () { return []; }),
      NS.cookies.getAll({ domain: "google.com" }).catch(function () { return []; }),
    ]).then(function (lists) {
      var seen = {};
      lists.forEach(function (list) {
        list.forEach(function (c) { seen[c.name] = c.value; });
      });
      return Object.keys(seen).map(function (k) { return k + "=" + seen[k]; }).join("; ");
    });
  }

  // Background pages have host permissions, so this fetch is not CORS-limited.
  // Cookies are sent automatically for the target origin.
  function proxyFetch(input, init) {
    init = init || {};
    if (init.credentials === undefined) init.credentials = "include";
    return fetch(input, init);
  }

  function download(msg, onProgress) {
    if (!self.YTDownloader || typeof self.YTDownloader.download !== "function") {
      return Promise.reject(new Error("Downloader bundle not loaded"));
    }
    return cookieString().then(function (cookie) {
      return self.YTDownloader.download({
        videoId: msg.videoId,
        cookie: cookie,
        kind: msg.kind,
        quality: msg.quality,
        fetch: proxyFetch,
      }, onProgress);
    }).then(function (res) {
      var url = URL.createObjectURL(res.blob);
      return NS.downloads.download({ url: url, filename: res.filename, saveAs: false })
        .then(function (id) {
          setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
          return { ok: true, downloadId: id, filename: res.filename };
        });
    });
  }

  self.BOTIM_YT = { download: download };
})();
