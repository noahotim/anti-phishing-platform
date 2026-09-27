"""Export YouTube cookies from a local browser and upload them to the guard server.

This is the step that makes downloads work on the videos YouTube refuses to the server for.
Run it once, after signing in to youtube.com in a normal browser window.

    python store\yt_cookies.py --browser firefox
    python store\yt_cookies.py --browser chrome

Then sign out of YouTube everywhere, because these cookies are a live login.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

SERVER = "https://phishguard-8vri.onrender.com"
HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "cookies.txt"


def export(browser: str) -> str:
    """Ask yt-dlp to read the browser's cookie jar and write it to cookies.txt."""
    import yt_dlp

    probe = HERE / "_probe.mp4"
    opts = {
        "cookiesfrombrowser": (browser, None, None),
        "cookies": str(OUT),
        "skip_download": True,
        "quiet": True,
        "noplaylist": True,
    }
    with yt_dlp.YoutubeDL(opts) as ydl:
        ydl.extract_info("https://www.youtube.com/", download=False)
    if probe.exists():
        probe.unlink()
    if not OUT.exists() or OUT.stat().st_size < 20:
        raise RuntimeError("yt-dlp did not write a usable cookies.txt")
    return str(OUT)


def login(email: str) -> str:
    body = json.dumps({"email": email, "password": os.environ.get("GUARD_PASSWORD", "")}).encode()
    req = urllib.request.Request(
        SERVER + "/api/auth/login", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode())
    return data.get("access_token") or data.get("token") or ""


def upload(token: str) -> dict:
    raw = OUT.read_text(encoding="utf-8", errors="replace")
    req = urllib.request.Request(
        SERVER + "/api/youtube/cookies", data=raw.encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", default="firefox", choices=["firefox", "chrome", "edge"])
    ap.add_argument("--email", default="", help="admin email on your guard server")
    ap.add_argument("--keep", action="store_true", help="keep the local cookies.txt copy")
    args = ap.parse_args()

    if not args.email:
        print("error: pass --email with the admin email you log in with", file=sys.stderr)
        return 2
    if not os.environ.get("GUARD_PASSWORD"):
        print("error: set GUARD_PASSWORD in the environment first", file=sys.stderr)
        return 2

    print("1/4 reading cookies out of " + args.browser)
    try:
        export(args.browser)
    except Exception as e:  # noqa: BLE001
        print("   failed: " + str(e), file=sys.stderr)
        print("   Tip: open youtube.com in that browser and sign in first, "
              "and close the browser if it is Chrome or Edge.", file=sys.stderr)
        return 1
    size = OUT.stat().st_size
    print("   wrote " + str(size) + " bytes")

    print("2/4 signing in to the guard server")
    try:
        token = login(args.email)
    except urllib.error.HTTPError as e:
        print("   login failed: HTTP " + str(e.code), file=sys.stderr)
        return 1
    if not token:
        print("   no token returned, check the email and password", file=sys.stderr)
        return 1

    print("3/4 uploading")
    try:
        res = upload(token)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print("   upload failed: HTTP " + str(e.code) + " " + body[:200], file=sys.stderr)
        return 1
    print("   server stored " + str(res.get("size")) + " bytes")

    if not args.keep:
        OUT.unlink()
        print("4/4 removed the local copy of cookies.txt")
    else:
        print("4/4 local copy kept at " + str(OUT) + " (delete it yourself)")

    print("\nNow sign out of YouTube everywhere. Those cookies were a live login to your account.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
