# syntax=docker/dockerfile:1
#
# Package sources are build arguments. They default to the public registries so
# a clean clone builds anywhere; internal builds override them to point at the
# caching registry, which enforces the CVE block policy:
#
#   docker build --build-arg PIP_INDEX_URL="$PIP_INDEX_URL" \
#                --build-arg NPM_CONFIG_REGISTRY="$NPM_CONFIG_REGISTRY" .
#
# Both are read natively by their tool, and being ARGs they are build-time only,
# so no internal address is baked into the published image. A build container
# that cannot resolve the internal DNS zone also needs --add-host.
ARG PIP_INDEX_URL=https://pypi.org/simple/
ARG NPM_CONFIG_REGISTRY=https://registry.npmjs.org/

# ---- Stage 1: build the Vue frontend ----
FROM node:22-alpine AS frontend
ARG NPM_CONFIG_REGISTRY
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
# The lockfile keeps upstream registry.npmjs.org URLs; npm's default
# replace-registry-host=npmjs rewrites them to whichever registry is configured,
# so the lock stays usable both inside and outside the network.
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: backend runtime, serving API + built SPA ----
FROM python:3.12-slim
ARG PIP_INDEX_URL
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Persist the DB on a mounted volume, not in the image.
ENV DATABASE_URL=sqlite:////data/adguard_admin.db

COPY backend/requirements.txt .
# The base image ships a pip with its own advisories (CVE-2026-8643 and
# friends), and it stays in the final image where a scanner will find it — so
# upgrade it first, then install against it.
RUN pip install --no-cache-dir --upgrade "pip>=26.2" \
 && pip install --no-cache-dir -r requirements.txt

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
