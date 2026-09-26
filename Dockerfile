# ==========================================
# RECON-WIRE Multi-Stage Production Dockerfile
# ==========================================

# Stage 1: Build & wheels
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    git \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# Stage 2: Minimal Runtime Image
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="RECON-WIRE"
LABEL org.opencontainers.image.description="Next-Generation Cyber-Reconnaissance & Attack Surface Intelligence Engine"
LABEL org.opencontainers.image.authors="RECON-WIRE Team <security@reconwire.io>"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/0xK3rnelX/recon-wire"

# Set runtime environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TERM=xterm-256color \
    LANG=C.UTF-8

WORKDIR /app

# Install runtime dependencies (e.g. whois client)
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install pre-built python wheels
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Create non-root unprivileged security user
RUN useradd -m -u 1000 -s /bin/bash recon && \
    mkdir -p /app/output && \
    chown -R recon:recon /app

# Copy application code
COPY --chown=recon:recon . /app

# Install package locally
RUN pip install --no-cache-dir -e .

USER recon

# Volume for persistent export artifacts
VOLUME ["/app/output"]

ENTRYPOINT ["recon-wire"]
CMD ["--help"]
