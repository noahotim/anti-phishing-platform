// Offscreen document: has the extension's host permissions (so it can fetch
// YouTube / googlevideo cross-origin without CORS) and can call chrome.downloads.
// It embeds the sandboxed page (which can run eval) and relays messages.
(function () {
  var NS = (typeof browser !== "undefined" && browser) ? browser : chrome;
  var iframe = document.getElementById("sb");
  var sandboxReady = false;
  var readyWaiters = [];
  var jobs = new Map();

  function asError(err) { return String((err && err.message) || err); }

  window.addEventListener("message", function (ev) {
    var d = ev.data || {};
    if (!d || !d.type) return;

    if (d.type === "yt-ready") {
      sandboxReady = true;
      var waiters = readyWaiters.splice(0);
      waiters.forEach(function (fn) { fn(); });
      return;
    }

    if (d.type === "net") { handleNet(d); return; }

    var job = jobs.get(d.id);
    if (!job) return;
    if (d.type === "yt-progress") {
      if (job.onProgress) job.onProgress(d.bytes);
      return;
    }
    if (d.type === "yt-done") { jobs.delete(d.id); job.resolve(d); return; }
    if (d.type === "yt-error") { jobs.delete(d.id); job.reject(new Error(d.error)); }
  });

  function handleNet(m) {
    var reply = { type: "net-result", id: m.id };
    var init = { method: m.method || "GET", headers: m.headers || {}, credentials: "include" };
    if (m.body != null && m.method !== "GET" && m.method !== "HEAD") init.body = m.body;
    fetch(m.url, init).then(function (res) {
      return res.arrayBuffer().then(function (buf) {
        var headers = {};
        res.headers.forEach(function (v, k) { headers[k] = v; });
        reply.status = res.status;
        reply.headers = headers;
        reply.body = buf;
        iframe.contentWindow.postMessage(reply, "*", [buf]);
      });
    }).catch(function (err) {
      reply.error = asError(err);
      iframe.contentWindow.postMessage(reply, "*");
    });
  }

  function waitReady() {
    if (sandboxReady) return Promise.resolve();
    return new Promise(function (resolve) { readyWaiters.push(resolve); });
  }

  function run(msg) {
    return waitReady().then(function () {
      var id = "dl-" + Date.now() + "-" + Math.random().toString(36).slice(2);
      return new Promise(function (resolve, reject) {
        jobs.set(id, {
          resolve: resolve,
          reject: reject,
          onProgress: function (bytes) {
            try { NS.runtime.sendMessage({ type: "yt-progress", jobId: msg.jobId, bytes: bytes }); } catch (e) {}
          },
        });
        iframe.contentWindow.postMessage({
          type: "yt-download",
          id: id,
          videoId: msg.videoId,
          cookie: msg.cookie,
          kind: msg.kind,
          quality: msg.quality,
        }, "*");
      });
    }).then(function (result) {
      var url = URL.createObjectURL(result.blob);
      return NS.downloads.download({ url: url, filename: result.filename, saveAs: false })
        .then(function (downloadId) {
          setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
          return { ok: true, downloadId: downloadId, filename: result.filename };
        });
    });
  }

  NS.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (!msg || msg.type !== "offscreen:yt-download") return;
    run(msg).then(sendResponse).catch(function (err) {
      sendResponse({ ok: false, error: asError(err) });
    });
    return true;
  });
})();
