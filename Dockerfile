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
RUN mkdir -p /data

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
# The SPA build lands in /app/static, which app.main serves as a fallback route.
COPY --from=frontend /frontend/dist ./static

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
