# =============================================================================
# OpenRange — Production All-in-One Dockerfile
# =============================================================================
# Python 3.11 base image with system packages available for procedural
# service provisioning.  The OpenEnv server (uvicorn) is the only process
# started at boot — individual services (mysql, nginx, slapd, …) are
# started/stopped dynamically by RangeEnvironment.reset() based on the
# active snapshot manifest.  No services are hardcoded.
# =============================================================================

FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# ── 1. System packages ───────────────────────────────────────────────────────
# Install the *superset* of packages that any tier might need.
# The Builder/manifest decides which ones actually run per episode.

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
    # Recon & exploitation (available to agents via subprocess)
    nmap \
    netcat-openbsd dnsutils tcpdump curl wget sshpass \
    iputils-ping whois \
    # Utilities
    jq procps iproute2 git ca-certificates bash \
    && rm -rf /var/lib/apt/lists/*

# Python-based security tools (not in Debian repos)
RUN pip install --no-cache-dir sqlmap

# ── 2. Install uv for dependency management ──────────────────────────────────

RUN pip install --no-cache-dir uv

# ── 3. Create base directories ───────────────────────────────────────────────

RUN mkdir -p /var/log/siem/consolidated /run/sshd \
    /var/run/mysqld /var/log/mysql /var/log/nginx \
    && chown mysql:mysql /var/run/mysqld /var/log/mysql 2>/dev/null || true \
    && chmod 755 /var/log/siem

# ── 4. Copy application code and install Python deps ─────────────────────────

WORKDIR /app
COPY . /app/env
WORKDIR /app/env

RUN uv venv --python python3.11 /app/.venv \
    && . /app/.venv/bin/activate \
    && if [ -f uv.lock ]; then \
        uv sync --frozen --no-editable; \
    else \
        uv sync --no-editable; \
    fi

# ── 5. Environment ───────────────────────────────────────────────────────────

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env/src:/app/env:$PYTHONPATH"
ENV OPENRANGE_EXECUTION_MODE=subprocess

# ── 6. Health check ──────────────────────────────────────────────────────────

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

# ── 7. Start only the OpenEnv server — services are snapshot-driven ──────────

CMD ["python3", "-m", "uvicorn", "open_range.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
