FROM node:22-bookworm-slim AS potdeps
# The YouTube PO-token sidecar (bgutil) server dependencies, built from the
# pinned release tag so the source run in the final stage stays reproducible.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/bgutil
RUN curl -fsSL https://github.com/Brainicism/bgutil-ytdlp-pot-provider/archive/refs/tags/2.0.2.tar.gz \
    | tar -xz --strip-components=1
WORKDIR /opt/bgutil/server
RUN npm ci --omit=dev --no-audit --no-fund \
    || { echo "WARNING: PO-token server deps failed, sidecar will be limited"; mkdir -p node_modules; }

FROM python:3.11-slim
WORKDIR /app

# ffmpeg is required to produce mp3 audio and to merge video+audio streams.
# curl is required to install Deno, which runs the PO-token sidecar.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates curl \
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

# The YouTube PO-token client plugin, pinned to the same release as the server below.
RUN pip install --no-cache-dir "bgutil-ytdlp-pot-provider==2.0.2" \
    || echo "WARNING: PO-token plugin not installed, YouTube downloads will be limited"

# The PO-token server runs from source: the old release-zip URL 404'd, which left
# YouTube's bot check unsolved and blocked every download on the datacentre IP.
COPY --from=potdeps /opt/bgutil/server /opt/bgutil/server
RUN deno cache --frozen /opt/bgutil/server/src/main.ts \
    || echo "WARNING: PO-token server cache failed, will resolve on first start"

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
# Its dependency tree lives in node_modules, so Deno only needs read/ffi there.
CMD ["sh", "-c", "mkdir -p /app/data && (deno run --allow-env --allow-net --allow-ffi=/opt/bgutil/server/node_modules --allow-read=/opt/bgutil/server/node_modules /opt/bgutil/server/src/main.ts -p ${BGUTIL_PORT:-4416} > /tmp/pot.log 2>&1 &) ; sleep 5 ; exec python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000} --app-dir /app/backend"]
