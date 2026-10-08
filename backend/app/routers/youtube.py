"""YouTube download helpers for BOTIMPHISHGUARD browser guard.

YouTube blocks plain datacentre requests with "Sign in to confirm you're not a
bot". We work around it in three layers:
  1. try each yt-dlp player client until one is not blocked for that video,
  2. use yt-dlp's default extra (yt-dlp-ejs), required for the JS challenge,
  3. use YouTube cookies if an admin has uploaded them.
"""
from __future__ import annotations

import os
import socket
import tempfile
from fastapi import APIRouter, Depends, Query, Request, HTTPException
from fastapi.responses import FileResponse

from ..security import get_current_user, require_role

router = APIRouter(prefix="/api/youtube", tags=["youtube"])

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# Tried one at a time, most to least likely to work from a datacentre IP.
# Different clients hit different bot-check rules, so one of these usually gets
# through for a given video. Order is based on a live test (yt-dlp 2026.08.19,
# datacentre IP): android_creator, android_testsuite, android_music and the
# default client all returned full format lists, while tv_simply, web_safari,
# mweb, tv, ios, web_embedded and web_creator were refused outright.
PLAYER_CLIENTS = [
    "android_creator",
    "android_testsuite",
    "android_music",
    None,  # yt-dlp defaults; also passes the bot check
    "android_vr",
    # Last resort: refused from a datacentre IP, but may work for some videos
    # or when an admin has uploaded YouTube cookies.
    "tv_simply",
    "tv",
    "web_safari",
    "mweb",
    "ios",
    "web_embedded",
    "web_creator",
]

# The client that worked most recently. Tried first on the next request so we
# stop re-paying the cost of the failing clients in front of it.
_last_good_client: str | None = None

_COOKIE_FILE: str | None = None


def _cookie_cache_path() -> str:
    data_dir = os.path.dirname(os.environ.get("DATABASE_PATH", "/app/data/antiphishing.db"))
    data_dir = data_dir or "/app/data"
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "yt_cookies.txt")


def _load_uploaded_cookies() -> str | None:
    """Cookies an admin uploaded through the dashboard, if any."""
    p = _cookie_cache_path()
    try:
        if os.path.isfile(p) and os.path.getsize(p) > 10:
            return p
    except OSError:
        pass
    return None


def _cookie_file() -> str | None:
    """Optional YouTube cookies. Uploaded cookies win, then env, then none.

    Cookies are what lift YouTube's bot check on datacentre IPs, so an admin
    upload makes downloads work on videos every player client gets refused for.
    """
    global _COOKIE_FILE
    if _COOKIE_FILE is not None:
        return _COOKIE_FILE or None
    path = os.environ.get("YTDLP_COOKIES_FILE")
    if path and os.path.isfile(path):
        # Render mounts secret files read-only, but yt-dlp rewrites the cookie
        # jar after every extraction (Errno 30 without this copy).
        try:
            fd, tmp = tempfile.mkstemp(prefix="yt_cookies_", suffix=".txt")
            with open(path, "rb") as src, os.fdopen(fd, "wb") as dst:
                dst.write(src.read())
            path = tmp
        except OSError:
            path = None
    else:
        path = None
    if not path:
        path = _load_uploaded_cookies()
    if not path:
        raw = os.environ.get("YTDLP_COOKIES")
        if raw:
            fd, tmp = tempfile.mkstemp(prefix="yt_cookies_", suffix=".txt")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw)
            path = tmp
    _COOKIE_FILE = path or ""
    return path or None


def _sidecar_up() -> bool:
    """True when the PO-token sidecar is listening inside the container."""
    try:
        with socket.create_connection(("127.0.0.1", int(POT_PORT)), timeout=1):
            return True
    except OSError:
        return False


@router.get("/cookies")
def cookie_status(user=Depends(require_role("ADMIN", "SUPER_ADMIN"))):
    """Whether YouTube cookies are loaded. Admin only."""
    p = _cookie_file()
    return {
        "loaded": bool(p),
        "source": "upload" if (p and p == _load_uploaded_cookies()) else ("env" if p else None),
        "size": os.path.getsize(p) if p and os.path.isfile(p) else 0,
        "sidecar": _sidecar_up(),
    }


@router.post("/cookies")
async def cookie_upload(
    request: Request,
    user=Depends(require_role("ADMIN", "SUPER_ADMIN")),
):
    """Upload a Netscape cookies.txt from a signed-in YouTube session (admin only)."""
    global _COOKIE_FILE
    raw = (await request.body()).decode("utf-8", "replace")
    if "# Netscape HTTP Cookie File" not in raw and ".youtube.com" not in raw:
        raise HTTPException(status_code=400, detail="that is not a cookies.txt file")
    if len(raw) < 20:
        raise HTTPException(status_code=400, detail="cookies file is empty")
    path = _cookie_cache_path()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw)
    _COOKIE_FILE = path
    return {"ok": True, "size": len(raw)}


@router.delete("/cookies")
def cookie_delete(user=Depends(require_role("ADMIN", "SUPER_ADMIN"))):
    global _COOKIE_FILE
    p = _load_uploaded_cookies()
    if p and os.path.isfile(p):
        os.remove(p)
    _COOKIE_FILE = None
    return {"ok": True}


def _yt_dlp_available() -> bool:
    try:
        import yt_dlp  # type: ignore  # noqa: F401
        return True
    except ImportError:
        return False


POT_PORT = os.environ.get("BGUTIL_PORT", "4416")


def _pot_args() -> dict:
    """YouTube requires a PO token for requests from datacentre IPs. The provider
    runs as a sidecar inside the container; if it is not up we carry on without,
    which still covers the videos YouTube does not challenge."""
    return {
        "youtubepot-bgutilhttp": {"base_url": f"http://127.0.0.1:{POT_PORT}"}
    }


def _base_opts() -> dict:
    opts = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "socket_timeout": 30,
        "retries": 3,
        "fragment_retries": 3,
        "extractor_retries": 2,
        "http_headers": {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
        "geo_bypass": True,
        "extractor_args": _pot_args(),
    }
    cf = _cookie_file()
    if cf:
        opts["cookiefile"] = cf
    return opts


def _opts_for_client(client):
    opts = _base_opts()
    if client:
        # merge, do not replace, or the PO token settings are lost
        opts["extractor_args"]["youtube"] = {"player_client": [client]}
    return opts


def _run_with_fallbacks(build_opts, url, download):
    """Try each player client until one works. Returns the yt-dlp info dict."""
    import yt_dlp  # type: ignore

    global _last_good_client
    order = PLAYER_CLIENTS
    if _last_good_client is not None:
        order = [c for c in PLAYER_CLIENTS if (c or "default") == _last_good_client] + [
            c for c in PLAYER_CLIENTS if (c or "default") != _last_good_client
        ]
    errors = []
    for client in order:
        opts = _opts_for_client(client)
        try:
            opts.update(build_opts(client))
        except Exception as e:  # noqa: BLE001
            errors.append(f"{client or 'default'}: {e}")
            continue
        try:
            with yt_dlp.YoutubeDL(opts) as ydl:
                info = ydl.extract_info(url, download=download)
                if info:
                    _last_good_client = client or "default"
                    return info
        except Exception as e:  # noqa: BLE001
            errors.append(f"{client or 'default'}: {str(e)[:160]}")
    shown = errors if len(errors) <= 8 else errors[:4] + ["..."] + errors[-4:]
    raise HTTPException(
        status_code=502,
        detail=(
            "YouTube blocked every request from the server for this video. "
            "This is YouTube's anti-bot check on datacentre IPs, not a broken link. "
            + " | ".join(shown)
        ),
    )


def _check_url(url: str) -> None:
    if "youtube.com" not in url and "youtu.be" not in url:
        raise HTTPException(status_code=422, detail="not a youtube url")


@router.get("/info")
def youtube_info(url: str = Query(..., min_length=8, max_length=2048)):
    _check_url(url)
    if not _yt_dlp_available():
        from urllib.parse import urlparse, parse_qs
        vid = (parse_qs(urlparse(url).query).get("v", [""])[0] or url.split("/")[-1])[:20]
        return {
            "title": vid or "YouTube video",
            "uploader": "",
            "duration": None,
            "thumbnail": f"https://img.youtube.com/vi/{vid}/hqdefault.jpg" if vid else "",
            "url": url,
            "formats": ["mp4", "mp3"],
            "ytDlp": False,
        }
    info = _run_with_fallbacks(lambda c: {"skip_download": True}, url, False)
    return {
        "title": info.get("title") or "YouTube video",
        "uploader": info.get("uploader") or "",
        "duration": info.get("duration"),
        "thumbnail": info.get("thumbnail") or "",
        "url": url,
        "formats": ["mp4", "mp3"],
        "ytDlp": True,
    }


@router.get("/download")
def youtube_download(
    url: str = Query(..., min_length=8),
    format: str = Query(default="mp4", max_length=10),
    quality: str = Query(default="best", max_length=10),
):
    _check_url(url)
    fmt = format.lower().strip()
    if fmt not in ("mp4", "mp3", "m4a", "webm"):
        fmt = "mp4"
    if not _yt_dlp_available():
        raise HTTPException(status_code=501, detail="yt-dlp not installed on server")
    if fmt == "mp3" and not _has_ffmpeg():
        raise HTTPException(status_code=503, detail="server is still building audio support, try video in a minute")

    tmpdir = tempfile.mkdtemp(prefix="yt_")
    q = quality.lower().strip()

    if fmt == "mp3":
        qual = "320" if q == "best" else ("192" if q in ("192", "high") else "128")
        fmts = [
            "bestaudio[ext=m4a]",
            "bestaudio[ext=webm]",
            "bestaudio/best",
        ]
        post = [{
            "key": "FFmpegExtractAudio",
            "preferredcodec": "mp3",
            "preferredquality": qual,
        }]

        def build(clients, _fmts=fmts, _post=post):
            return {
                "format": "/".join(_fmts),
                "outtmpl": os.path.join(tmpdir, "%(title).80s.%(ext)s"),
                "postprocessors": _post,
            }
    else:
        cap = q if q in ("1080", "720", "480", "360", "240") else None
        if cap:
            fmts = [
                f"bestvideo[height<={cap}][ext=mp4]+bestaudio[ext=m4a]",
                f"bestvideo[height<={cap}][ext=mp4]+bestaudio",
                f"best[height<={cap}][ext=mp4]",
                f"best[height<={cap}]",
            ]
        else:
            fmts = [
                "bestvideo[ext=mp4]+bestaudio[ext=m4a]",
                "bestvideo[ext=mp4]+bestaudio",
                "best[ext=mp4]",
                "best",
            ]

        def build(clients, _fmts=fmts):
            return {
                "format": "/".join(_fmts),
                "outtmpl": os.path.join(tmpdir, "%(title).80s.%(ext)s"),
                "merge_output_format": "mp4",
            }

    _run_with_fallbacks(build, url, True)

    import glob
    files = [p for p in glob.glob(os.path.join(tmpdir, "*")) if os.path.isfile(p)]
    if not files:
        raise HTTPException(status_code=500, detail="download produced no file")
    fpath = max(files, key=os.path.getsize)
    media_type = "audio/mpeg" if fmt == "mp3" else "video/mp4"
    return FileResponse(
        fpath,
        media_type=media_type,
        filename=os.path.basename(fpath),
        background=None,
    )


def _has_ffmpeg() -> bool:
    import shutil
    return shutil.which("ffmpeg") is not None
