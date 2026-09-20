# syntax=docker/dockerfile:1.7

FROM python:3.12.7-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY app/requirements.txt ./requirements.txt

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt

FROM python:3.12.7-slim-bookworm AS runtime

ARG CURL_VERSION=7.88.1-10+deb12u15
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends curl=${CURL_VERSION} \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 appuser \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_PORT=80

COPY --from=builder --chown=root:root /opt/venv /opt/venv

WORKDIR /app

COPY --chown=root:root --chmod=0444 app/ /app/

USER 10001:10001

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:${APP_PORT}/healthz || exit 1

CMD ["python3", "/app/app.py"]
