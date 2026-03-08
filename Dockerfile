# syntax=docker/dockerfile:1.7

# =============================================================================
# OpenRange — Production All-in-One Dockerfile
# =============================================================================
# Multi-stage build:
#   1) deps: resolve third-party Python dependencies with official uv image
#   2) runtime: install system services/tools, then copy app source as last step
# =============================================================================

ARG UV_IMAGE=ghcr.io/astral-sh/uv:python3.11-bookworm-slim

FROM ${UV_IMAGE} AS deps

WORKDIR /app/env

# Install git only for potential git+ dependencies during uv sync.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-editable \
    && uv pip install --python .venv/bin/python sqlmap

FROM ${UV_IMAGE} AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install base packages that all tiers need. Higher tiers add extras via the
# TIER_PACKAGES build arg (tier1, tier2, tier3).
ARG TIER_PACKAGES="tier1"

# --- Tier 1 (base) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Web
    nginx \
    # Database
    default-mysql-server default-mysql-client \
    # LDAP
    slapd ldap-utils \
    # Logging
    rsyslog \
    # File sharing
    samba \
    # Mail
    postfix \
    # SSH
    openssh-server \
    # SMB client (for agent enumeration)
    smbclient \
    # Recon & exploitation (available to agents via subprocess)
    nmap \
    netcat-openbsd dnsutils tcpdump curl wget sshpass \
    iputils-ping whois \
    # Utilities
    jq procps iproute2 ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*

# --- Tier 2 (+ VPN, cron) ---
RUN if echo "${TIER_PACKAGES}" | grep -qE "tier[2-9]"; then \
        apt-get update && apt-get install -y --no-install-recommends \
            openvpn easy-rsa cron \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# --- Tier 3 (+ Redis, PostgreSQL, CI tooling) ---
RUN if echo "${TIER_PACKAGES}" | grep -qE "tier[3-9]"; then \
        apt-get update && apt-get install -y --no-install-recommends \
            redis-server postgresql postgresql-client \
        && rm -rf /var/lib/apt/lists/*; \
    fi

RUN mkdir -p /var/log/siem/consolidated /run/sshd \
    /var/run/mysqld /var/log/mysql /var/log/nginx \
    && chown mysql:mysql /var/run/mysqld /var/log/mysql 2>/dev/null || true \
    && chmod 755 /var/log/siem

WORKDIR /app/env
COPY --from=deps /app/env/.venv /app/env/.venv
COPY . /app/env

ENV PATH="/app/env/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env/src:/app/env"
ENV OPENRANGE_EXECUTION_MODE=subprocess
# Enable the managed runtime so reset() boots real services from the manifest
ENV OPENRANGE_RUNTIME_MANIFEST=manifests/tier1_basic.yaml
ENV OPENRANGE_RUNTIME_VALIDATOR_PROFILE=training
ENV OPENRANGE_ENABLE_LIVE_ADMISSION=1
ENV OPENRANGE_SNAPSHOT_POOL_SIZE=1
# Enable the OpenEnv Gradio web interface at /web
ENV ENABLE_WEB_INTERFACE=true

# Clear any pre-existing snapshots so runtime always generates fresh ones
# with current service specs from service_manifest.py
RUN rm -rf /app/env/snapshots/* 2>/dev/null || true

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

# Start only the OpenEnv server; services are snapshot-driven.
CMD ["python", "-m", "uvicorn", "open_range.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
