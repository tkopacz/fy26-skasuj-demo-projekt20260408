# Stage 1: Builder — install Python dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and install dependencies into an isolated prefix
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install --prefix=/install \
        "cryptography>=41.0" \
        "PyYAML>=6.0" \
        "protobuf>=4.25" \
        "aiohttp>=3.9"

# Copy application source
COPY tactical_relay/ ./tactical_relay/

# Install the package itself
RUN pip install --prefix=/install --no-deps .


# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with non-root user
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Create a non-root system user
RUN groupadd --system relay && \
    useradd --system --gid relay --home /app --shell /usr/sbin/nologin relay

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --from=builder /build/tactical_relay ./tactical_relay/

# Create runtime directories and set ownership
RUN mkdir -p certs data logs config && \
    chown -R relay:relay /app

# Default configuration (override with volume mount)
COPY config.yaml ./
COPY config/routing_rules.yaml ./config/

# Switch to non-root user
USER relay

# Transport port (mTLS)
EXPOSE 8443
# Health / metrics port
EXPOSE 8080

# Health check against the HTTP health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

# The RELAY_AUDIT_HMAC_SECRET env var MUST be provided at runtime
ENV RELAY_LOG_LEVEL=INFO

ENTRYPOINT ["python", "-m", "tactical_relay.main"]
CMD ["--config", "config.yaml"]
