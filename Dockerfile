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

# The Python images for the dependency stage and the runtime stage. Both default
# to python:3.14-slim. To build on a hardened, shell-less runtime instead, point
# them at a matching pair: a "-dev" image with a shell and pip to install into,
# and its runtime sibling to ship. CI does this when USE_DHI=true (Docker
# Hardened Images; see .gitlab-ci.yml).
#
#   docker build \
#     --build-arg PYTHON_BUILDER_IMAGE=dhi.io/python:3.14-alpine-dev \
#     --build-arg PYTHON_RUNTIME_IMAGE=dhi.io/python:3.14-alpine .
#
# The two must come from the same family: packages built against glibc in a
# slim builder will not load on a musl (Alpine) runtime, and vice versa.
ARG PYTHON_BUILDER_IMAGE=python:3.14-slim
ARG PYTHON_RUNTIME_IMAGE=python:3.14-slim

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

# ---- Stage 2: install the backend's Python dependencies ----
FROM ${PYTHON_BUILDER_IMAGE} AS python-deps
ARG PIP_INDEX_URL
ENV PIP_NO_CACHE_DIR=1 PIP_ROOT_USER_ACTION=ignore
COPY backend/requirements.txt /tmp/requirements.txt
# --target rather than --prefix or a venv: a plain directory on PYTHONPATH
# does not depend on where the interpreter lives, which differs between the
# slim image (/usr/local) and the hardened one (/usr). The resolver is upgraded
# first so the version doing the resolving is a patched one (CVE-2026-8643).
RUN pip install --upgrade "pip>=26.2" \
 && pip install --target=/opt/pydeps -r /tmp/requirements.txt \
 && mkdir -p /skel/data

# ---- Stage 3: backend runtime, serving API + built SPA ----
#
# No RUN steps in this stage. The hardened runtime has no shell, so everything
# here is a COPY or metadata, and the stage builds the same way on either base.
FROM ${PYTHON_RUNTIME_IMAGE}
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/pydeps
# Persist the DB on a mounted volume, not in the image.
ENV DATABASE_URL=sqlite:////data/adguard_admin.db

# Code and dependencies are root-owned, so the app process can read them but
# not change them.
COPY --from=python-deps /opt/pydeps /opt/pydeps
COPY backend/app ./app
# The SPA build lands in /app/static, which app.main serves as a fallback route.
COPY --from=frontend /frontend/dist ./static
COPY backend/docker-entrypoint.py /usr/local/bin/docker-entrypoint.py

# /data is the only path the app writes (SQLite plus its WAL and shared-memory
# sidecars). It ships owned by the app user, so a fresh named volume inherits
# that ownership on first mount. Numeric ids, because the uid has no passwd
# entry; nothing looks it up.
COPY --from=python-deps --chown=10001:10001 /skel/data /data

# The application always runs as uid 10001, but the container starts as root:
# the entrypoint repairs a data volume left root-owned by an older build, then
# drops privileges before exec'ing the app (backend/docker-entrypoint.py). The
# hardened base defaults to a non-root user, so root is set explicitly here.
# Set `user: "10001:10001"` in compose to skip the root phase entirely once the
# volume's ownership is correct.
USER 0:0

EXPOSE 8000

# The container is unhealthy if the API stops answering, not merely if the
# process is alive — the reconcile loop can outlive a wedged event loop.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["python", "/usr/local/bin/docker-entrypoint.py"]
# `python -m`: the uvicorn launcher script is in /opt/pydeps/bin, not on PATH.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
