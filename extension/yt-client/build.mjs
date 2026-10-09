// Bundles src/entry.js (youtubei.js + bgutils-js + our glue) into a single
// classic script the sandbox page can load. Run:  npm install && npm run build
import { build } from "esbuild";

await build({
  entryPoints: ["src/entry.js"],
  bundle: true,
  format: "iife",
  globalName: "YTDownloader",
  outfile: "../vendor/yt-download.js",
  platform: "browser",
  target: ["chrome109", "firefox115"],
  legalComments: "none",
  logLevel: "info",
});
