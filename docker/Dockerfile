FROM python:3.14-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir --prefix=/install ".[server,cli]"

FROM python:3.14-slim

LABEL org.opencontainers.image.source="https://github.com/kobepaw/goop-shield-community" \
      org.opencontainers.image.description="Runtime defense for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="goop-shield"

WORKDIR /app

RUN groupadd -r shield && useradd -r -g shield -d /app shield

COPY --from=builder /install /usr/local
COPY config/ config/

RUN chown -R shield:shield /app

USER shield

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8787/api/v1/health')"]

ENTRYPOINT ["goop-shield", "serve", "--host", "0.0.0.0"]
