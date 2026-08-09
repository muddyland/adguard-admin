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
COPY backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The application always runs as an unprivileged user. /data is the only path it
# needs to write (SQLite plus its WAL and shared-memory sidecars), so it is owned
# by the app user while the code itself stays read-only to the process.
#
# The entrypoint, not the USER directive, drops the privileges. Starting as root
# lets it repair a data volume left root-owned by an older build before handing
# off; see backend/docker-entrypoint.sh. Set `user: "10001:10001"` in compose to
# skip the root phase entirely once the volume's ownership is correct.
RUN useradd --system --create-home --uid 10001 appuser \
 && mkdir -p /data \
 && chown -R appuser:appuser /data \
 && chown -R root:root /app && chmod -R a-w /app \
 && chmod 0755 /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000

# The container is unhealthy if the API stops answering, not merely if the
# process is alive — the reconcile loop can outlive a wedged event loop.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
