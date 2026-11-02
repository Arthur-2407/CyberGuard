# syntax=docker/dockerfile:1
# ═══════════════════════════════════════════════════════════════════════════════
# CyberGuard Enterprise SOC & AI Multi-Modal Defense Platform
# Production Hardened Dockerfile (Optimized CPU Inference & Fast Startup)
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.12-slim-bookworm

LABEL maintainer="CyberGuard Core Security Team" \
      service="cyberguard-backend" \
      version="1.0.0" \
      description="CyberGuard SOC Threat Intelligence & Multi-Modal AI Defense Backend"

# Stop interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PORT=3000 \
    DATABASE_PATH=/app/data/cyberguard.db \
    OMP_NUM_THREADS=2 \
    MKL_NUM_THREADS=2 \
    OPENBLAS_NUM_THREADS=2

# Install critical system libraries for audio DSP, QR decoding, health probes, and ClamAV local antivirus
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsndfile1 \
    ffmpeg \
    libzbar0 \
    libportaudio2 \
    curl \
    ca-certificates \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pre-install pip tools and lightweight CPU-only PyTorch to avoid massive CUDA blobs
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r /app/backend/requirements.txt

# Create dedicated non-root application user and persistent data structures
RUN groupadd -g 10001 cyberguard && \
    useradd -u 10001 -g cyberguard -G clamav -s /bin/bash -m cyberguard && \
    mkdir -p /app/data /app/backend/models/weights /app/frontend /var/lib/clamav /var/log/clamav /var/run/clamav

# Copy application backend, frontend static assets, helper scripts, and core configuration
COPY backend /app/backend
COPY frontend /app/frontend
COPY data/yara_rules /app/data/yara_rules
COPY scripts/docker-entrypoint.sh /app/scripts/docker-entrypoint.sh
COPY config.yaml /app/config.yaml
COPY index.html /app/index.html
COPY .env.example /app/.env.example

# Set proper ownership for non-root execution and ClamAV signature database access
RUN chmod +x /app/scripts/*.sh 2>/dev/null || true && \
    sed -i 's/^DatabaseOwner .*/DatabaseOwner cyberguard/' /etc/clamav/freshclam.conf 2>/dev/null || true && \
    sed -i 's/^User .*/User cyberguard/' /etc/clamav/clamd.conf 2>/dev/null || true && \
    echo 'TCPSocket 3310' >> /etc/clamav/clamd.conf 2>/dev/null || true && \
    echo 'TCPAddr 127.0.0.1' >> /etc/clamav/clamd.conf 2>/dev/null || true && \
    chown -R cyberguard:cyberguard /app /var/lib/clamav /var/log/clamav /var/run/clamav && \
    chmod -R 775 /var/lib/clamav /var/log/clamav /var/run/clamav

USER cyberguard

EXPOSE 3000

# Docker native container health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Launch production ASGI server on configurable port via initialization entrypoint
ENTRYPOINT ["/bin/bash", "/app/scripts/docker-entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "3000"]
