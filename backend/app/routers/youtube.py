"""YouTube download helpers for BOTIMPHISHGUARD browser guard."""
from __future__ import annotations

import os
import tempfile
import subprocess
import json
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import FileResponse, JSONResponse

router = APIRouter(prefix="/api/youtube", tags=["youtube"])


def _yt_dlp_available() -> bool:
    try:
        import yt_dlp  # type: ignore
        return True
    except ImportError:
        return False


@router.get("/info")
def youtube_info(url: str = Query(..., min_length=8, max_length=2048)):
    if "youtube.com" not in url and "youtu.be" not in url:
        raise HTTPException(status_code=422, detail="not a youtube url")
    if not _yt_dlp_available():
        # fallback mock — still allows frontend to show buttons
        vid = ""
        try:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(url).query)
            vid = (qs.get("v", [""])[0] or url.split("/")[-1])[:20]
        except Exception:
            vid = "video"
        return {
            "title": vid or "YouTube video",
            "uploader": "",
            "duration": None,
            "thumbnail": f"https://img.youtube.com/vi/{vid}/hqdefault.jpg" if vid else "",
            "url": url,
            "formats": ["mp4", "mp3"],
        }
    try:
        import yt_dlp  # type: ignore
        ydl_opts = {"quiet": True, "skip_download": True, "noplaylist": True}
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            return {
                "title": info.get("title") or "YouTube video",
                "uploader": info.get("uploader") or "",
                "duration": info.get("duration"),
                "thumbnail": info.get("thumbnail") or "",
                "url": url,
                "formats": ["mp4", "mp3"],
            }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"yt-dlp error: {e}")


@router.get("/download")
def youtube_download(url: str = Query(..., min_length=8), format: str = Query(default="mp4", max_length=10)):
    if "youtube.com" not in url and "youtu.be" not in url:
        raise HTTPException(status_code=422, detail="not a youtube url")
    fmt = format.lower().strip()
    if fmt not in ("mp4", "mp3", "m4a", "webm"):
        fmt = "mp4"
    if not _yt_dlp_available():
        raise HTTPException(status_code=501, detail="yt-dlp not installed on server — install via pip install yt-dlp")
    try:
        import yt_dlp  # type: ignore
        tmpdir = tempfile.mkdtemp(prefix="yt_")
        # yt-dlp options: best mp4 or best audio for mp3
        if fmt == "mp3":
            ydl_opts = {
                "format": "bestaudio/best",
                "outtmpl": os.path.join(tmpdir, "%(title)s.%(ext)s"),
                "postprocessors": [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3", "preferredquality": "192"}],
                "quiet": True,
                "noplaylist": True,
            }
        else:
            ydl_opts = {
                "format": "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best",
                "outtmpl": os.path.join(tmpdir, "%(title)s.%(ext)s"),
                "merge_output_format": "mp4",
                "quiet": True,
                "noplaylist": True,
            }
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            # find downloaded file
            import glob
            files = glob.glob(os.path.join(tmpdir, "*"))
            if not files:
                raise HTTPException(status_code=500, detail="download failed — no file")
            # pick largest file
            fpath = max(files, key=lambda p: os.path.getsize(p))
            filename = os.path.basename(fpath)
            # sanitize
            media_type = "audio/mpeg" if fmt == "mp3" else "video/mp4"
            return FileResponse(fpath, media_type=media_type, filename=filename, background=None)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"download error: {e}")
