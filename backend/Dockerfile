FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Default the DB to a persistent path so a bare `docker run -v vol:/data` keeps
# data outside the image. (compose mounts the named volume here too.)
ENV DATABASE_URL=sqlite:////data/adguard_admin.db
RUN mkdir -p /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
