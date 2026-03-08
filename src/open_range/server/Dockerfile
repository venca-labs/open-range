FROM python:3.11-slim AS builder

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml uv.lock* ./
COPY src/ src/
COPY openenv.yaml .
COPY manifests/ manifests/

# Install dependencies
RUN uv sync --frozen --no-editable 2>/dev/null || uv sync --no-editable

# --- Runtime stage ---
FROM python:3.11-slim

WORKDIR /app

# Runtime system deps: Docker CLI (for controlling range containers) + curl
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        docker.io \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/pyproject.toml /app/pyproject.toml
COPY --from=builder /app/openenv.yaml /app/openenv.yaml
COPY --from=builder /app/manifests /app/manifests
COPY server/ server/

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:$PYTHONPATH"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
