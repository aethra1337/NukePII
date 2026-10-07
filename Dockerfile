# NukePII — local-first PII engine (Flask + CLI).
# Build:  docker build -t nukepii .
# Run:    docker run --rm -p 5000:5000 nukepii
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NUKEPII_HOST=0.0.0.0 \
    NUKEPII_PORT=5000

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY nukepii ./nukepii
COPY rules ./rules

RUN pip install --upgrade pip && pip install -r requirements.txt && pip install .

# Drop privileges: the engine never needs root (temp files only).
RUN useradd -m -u 10001 nukepii && chown -R nukepii:nukepii /app
USER nukepii

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=4)"

# Single process + threads: /api/v1 job state lives in-process, so stay on
# one worker and scale concurrency with threads.
CMD ["sh", "-c", "waitress-serve --call --listen=0.0.0.0:${NUKEPII_PORT:-5000} --threads=8 nukepii.web.app:create_app"]
