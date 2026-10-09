// Runs inside the sandboxed page (declared under manifest.sandbox), where
// eval/new Function is permitted. All network is proxied to the offscreen
// document because sandboxed pages do not carry the extension's host
// permissions and therefore cannot make privileged cross-origin requests.
(function () {
  var seq = 0;
  var netPending = new Map();

  function toHeaders(h) {
    if (!h) return {};
    if (typeof Headers !== "undefined" && h instanceof Headers) {
      var out = {};
      h.forEach(function (v, k) { out[k] = v; });
      return out;
    }
    if (Array.isArray(h)) {
      var out2 = {};
      h.forEach(function (pair) { out2[pair[0]] = pair[1]; });
      return out2;
    }
    return Object.assign({}, h);
  }

  function proxyFetch(input, init) {
    init = init || {};
    var start = Promise.resolve(input);
    if (typeof Request !== "undefined" && input instanceof Request) {
      start = input.clone().arrayBuffer().then(function (buf) {
        return { url: input.url, method: input.method, headers: input.headers, body: buf };
      });
    } else {
      start = Promise.resolve(input);
    }
    return start.then(function (req) {
      var isReq = req && typeof req === "object" && typeof req.url === "string";
      var url = typeof req === "string" ? req : (req instanceof URL ? req.href : (isReq ? req.url : String(req)));
      var method = init.method || (isReq ? req.method : "GET") || "GET";
      var headers = toHeaders(init.headers || (isReq ? req.headers : null));
      var body = init.body != null ? init.body : (isReq ? req.body : null);
      if (body != null && typeof body !== "string") {
        if (body instanceof URLSearchParams) {
          body = body.toString();
        } else if (
          typeof ArrayBuffer !== "undefined" &&
          (body instanceof ArrayBuffer || ArrayBuffer.isView(body))
        ) {
          // Transferable as-is via structured clone.
        } else if (typeof Blob !== "undefined" && body instanceof Blob) {
          // Sent as-is; structured clone supports Blob.
        } else {
          try { body = JSON.stringify(body); } catch (e) { body = String(body); }
        }
      }
      var id = ++seq;
      return new Promise(function (resolve, reject) {
        netPending.set(id, { resolve: resolve, reject: reject });
        parent.postMessage(
          { type: "net", id: id, url: url, method: method, headers: headers, body: body },
          "*"
        );
      });
    });
  }

  function post(msg) { parent.postMessage(msg, "*"); }

  window.addEventListener("message", function (ev) {
    var d = ev.data || {};
    if (d.type === "net-result") {
      var p = netPending.get(d.id);
      if (!p) return;
      netPending.delete(d.id);
      if (d.error) { p.reject(new Error(d.error)); return; }
      p.resolve(new Response(d.body, { status: d.status || 200, headers: d.headers || {} }));
    }
  });

  window.addEventListener("message", function (ev) {
    var d = ev.data || {};
    if (d.type !== "yt-download") return;
    window.YTDownloader.download(
      { videoId: d.videoId, cookie: d.cookie, kind: d.kind, quality: d.quality, fetch: proxyFetch },
      function (bytes) { post({ type: "yt-progress", id: d.id, bytes: bytes }); }
    ).then(function (res) {
      post({ type: "yt-done", id: d.id, filename: res.filename, bytes: res.bytes, blob: res.blob });
    }).catch(function (err) {
      post({ type: "yt-error", id: d.id, error: String((err && err.message) || err) });
    });
  });

  post({ type: "yt-ready" });
})();
