FROM python:3.11-slim
WORKDIR /app

# ffmpeg is required to produce mp3 audio and to merge video+audio streams.
# curl and unzip are required to install Deno.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Deno gives yt-dlp the JavaScript runtime it needs for YouTube's challenge.
# This is best effort on purpose: if it cannot be installed the app still runs and
# only the hardest downloads are affected, which is far better than a failed deploy.
RUN (curl -fsSL https://deno.land/install.sh | sh) \
    && ln -sf /root/.deno/bin/deno /usr/local/bin/deno \
    && deno --version \
    || echo "WARNING: Deno not installed, YouTube challenge solving will be limited"

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# The YouTube PO-token client plugin. Also best effort, for the same reason.
RUN pip install --no-cache-dir "bgutil-ytdlp-pot-provider>=1.3.0" \
    || echo "WARNING: PO-token plugin not installed, YouTube downloads will be limited"

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
# Port the YouTube PO-token sidecar listens on inside the container.
ENV BGUTIL_PORT=4416
EXPOSE 10000
# The PO-token sidecar runs alongside the API and is started best effort.
CMD ["sh", "-c", "mkdir -p /app/data && (env PORT=${BGUTIL_PORT} deno run -A -n https://github.com/Brainicism/bgutil-ytdlp-pot-provider/archive/refs/heads/server.zip > /tmp/pot.log 2>&1 &) ; sleep 5 ; exec python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000} --app-dir /app/backend"]
