# syntax=docker/dockerfile:1
# ---- Stage 1: build the Vue frontend ----
FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: backend runtime, serving API + built SPA ----
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Persist the DB on a mounted volume, not in the image.
ENV DATABASE_URL=sqlite:////data/adguard_admin.db

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
# The SPA build lands in /app/static, which app.main serves as a fallback route.
COPY --from=frontend /frontend/dist ./static

# Run as an unprivileged user. /data is the only path that needs to be writable
# (SQLite plus its WAL and shared-memory sidecar files), so it is owned by the
# app user while the code itself stays read-only to the process.
RUN useradd --system --create-home --uid 10001 appuser \
 && mkdir -p /data \
 && chown -R appuser:appuser /data \
 && chown -R root:root /app && chmod -R a-w /app
USER appuser

EXPOSE 8000

# The container is unhealthy if the API stops answering, not merely if the
# process is alive — the reconcile loop can outlive a wedged event loop.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
