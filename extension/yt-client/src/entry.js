import { Innertube, Platform } from "youtubei.js/web";
import { BG } from "bgutils-js";

// PoToken request key used by the YouTube web client.
const REQUEST_KEY = "O43z0dpjhgX20SCx4KAo";

// youtubei.js deciphers stream signatures by running YouTube's player code.
// Extension pages forbid eval, but this file runs inside a *sandboxed* page
// (declared under manifest.sandbox), where `new Function` is allowed.
Platform.shim.eval = async (data) => new Function(data.output)();

function sanitise(name) {
  return (name || "youtube-video")
    .replace(/[\\/:*?"<>|]+/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

async function mintPoToken(fetchImpl, visitorData) {
  const bgConfig = {
    fetch: fetchImpl,
    globalObj: globalThis,
    identifier: visitorData,
    requestKey: REQUEST_KEY,
  };
  const challenge = await BG.Challenge.create(bgConfig);
  if (!challenge) return null;
  const interpreter =
    challenge.interpreterJavascript &&
    challenge.interpreterJavascript
      .privateDoNotAccessOrElseSafeScriptWrappedValue;
  if (interpreter) new Function(interpreter)();
  const result = await BG.PoToken.generate({
    program: challenge.program,
    globalName: challenge.globalName,
    bgConfig,
  });
  return result && result.poToken ? result.poToken : null;
}

// opts: { videoId, cookie, kind: "video"|"audio", quality, fetch }
// onProgress: (bytesReceived) => void
export async function download(opts, onProgress) {
  const { videoId, cookie, kind = "video", quality = "best", fetch: fetchImpl } = opts || {};
  if (!videoId) throw new Error("Missing videoId");
  if (typeof fetchImpl !== "function") throw new Error("Missing network bridge (fetch)");

  // All InnerTube/player/media requests go through the platform shim, so point
  // it at the proxied fetch (network actually runs in the offscreen document).
  Platform.shim.fetch = fetchImpl;

  const auth = cookie ? { cookie } : {};

  // 1. Bootstrap a session so we can read visitorData, then mint a PoToken.
  const probe = await Innertube.create({ ...auth, fetch: fetchImpl, retrieve_player: false });
  const visitorData = probe.session.context.client.visitorData;
  let poToken = null;
  try {
    poToken = await mintPoToken(fetchImpl, visitorData);
  } catch (err) {
    // A PoToken improves reliability but is not required for every video.
    poToken = null;
  }

  // 2. Fresh session carrying the PoToken, used for the actual download.
  const yt = await Innertube.create({
    ...auth,
    fetch: fetchImpl,
    visitor_data: visitorData,
    po_token: poToken,
  });

  const info = await yt.getInfo(videoId);
  const title = (info.basic_info && info.basic_info.title) || videoId;

  const downloadOpts =
    kind === "audio"
      ? { type: "audio", quality: "best", format: "mp4" }
      : { type: "video+audio", quality: quality || "best", format: "mp4" };

  let stream;
  try {
    stream = await info.download(downloadOpts);
  } catch (err) {
    stream = await info.download({ type: "video+audio", quality: "best", format: "mp4" });
  }

  const reader = stream.getReader();
  const parts = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    received += value.length;
    if (typeof onProgress === "function") {
      try { onProgress(received); } catch (_) { /* ignore */ }
    }
  }

  const mime = kind === "audio" ? "audio/mp4" : "video/mp4";
  const ext = kind === "audio" ? ".m4a" : ".mp4";
  const blob = new Blob(parts, { type: mime });
  return { blob, filename: sanitise(title) + ext, bytes: received, poToken: !!poToken };
}
