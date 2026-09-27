"""YouTube download helpers for BOTIMPHISHGUARD browser guard.

YouTube blocks plain datacenter requests with "Sign in to confirm you're not a
bot". We work around it by trying several player clients in turn and by using
yt-dlp's default extra (yt-dlp-ejs), which is required to solve the current
JS challenge.
"""
from __future__ import annotations

import os
import tempfile
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api/youtube", tags=["youtube"])

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# Ordered most to least likely to work from a datacentre IP.
CLIENT_SETS = [
    ["tv", "android_vr", "web_safari", "mweb"],
    ["android_vr", "ios", "web_safari"],
    ["web_embedded", "tv", "mweb"],
    ["ios", "android", "web"],
    None,  # last resort: yt-dlp defaults
]


def _yt_dlp_available() -> bool:
    try:
        import yt_dlp  # type: ignore  # noqa: F401
        return True
    except ImportError:
        return False


def _base_opts() -> dict:
    return {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "socket_timeout": 30,
        "retries": 5,
        "fragment_retries": 5,
        "http_headers": {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
        "geo_bypass": True,
    }


def _opts_for_clients(clients):
    opts = _base_opts()
    if clients:
        opts["extractor_args"] = {"youtube": {"player_client": clients}}
    return opts


def _run_with_fallbacks(build_opts, url, download):
    """Try each player client set until one works. Returns (ydl, info)."""
    import yt_dlp  # type: ignore

    errors = []
    for clients in CLIENT_SETS:
        opts = _base_opts()
        extra = build_opts(clients)
        opts.update(extra)
        try:
            with yt_dlp.YoutubeDL(opts) as ydl:
                info = ydl.extract_info(url, download=download)
                if info:
                    return info
        except Exception as e:  # noqa: BLE001
            errors.append(f"{clients or 'default'}: {e}")
    raise HTTPException(
        status_code=502,
        detail="YouTube refused the request from the server. " + " | ".join(errors[-3:]),
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
