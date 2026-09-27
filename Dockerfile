FROM python:3.11-slim
WORKDIR /app

# ffmpeg is required to produce mp3 audio and to merge video+audio streams.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY frontend/ ./frontend/
ENV PYTHONPATH=/app/backend
ENV HOST=0.0.0.0
ENV PORT=10000
ENV DATABASE_PATH=/app/data/antiphishing.db
ENV SEED_ON_STARTUP=true
EXPOSE 10000
CMD ["sh","-c","mkdir -p /app/data && python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000} --app-dir /app/backend"]
