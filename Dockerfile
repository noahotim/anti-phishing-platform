FROM python:3.11-slim
WORKDIR /app

# ffmpeg is required to produce mp3 audio and to merge video+audio streams.
# curl is required to install Deno.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Deno gives yt-dlp the JavaScript runtime it needs to solve YouTube's challenge.
RUN curl -fsSL https://deno.land/install.sh | sh \
    && ln -sf /root/.deno/bin/deno /usr/local/bin/deno \
    && deno --version

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY frontend/ ./frontend/
# The guard reads the extension manifest from here to serve /api/guard/version,
# which is what makes already-installed copies see new updates.
COPY extension/manifest.json ./extension/manifest.json
ENV PYTHONPATH=/app/backend
ENV HOST=0.0.0.0
ENV PORT=10000
ENV DATABASE_PATH=/app/data/antiphishing.db
ENV SEED_ON_STARTUP=true
# Port the background YouTube PO-token server listens on inside the container.
ENV BGUTIL_PORT=4416
EXPOSE 10000
# The PO-token server runs alongside the API. If it fails to start, downloads
# still work on the videos YouTube does not challenge, so it is best effort.
CMD ["sh", "-c", "mkdir -p /app/data && (deno run -A -n --port ${BGUTIL_PORT} https://github.com/Brainicism/bgutil-ytdlp-pot-provider/archive/refs/heads/server.zip > /tmp/pot.log 2>&1 &) ; sleep 8 ; exec python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000} --app-dir /app/backend"]
