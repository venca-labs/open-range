# syntax=docker/dockerfile:1.7

ARG UV_IMAGE=ghcr.io/astral-sh/uv:python3.11-bookworm-slim

FROM ${UV_IMAGE} AS deps

WORKDIR /app/env

# Install git for optional git+ dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-editable

FROM ${UV_IMAGE} AS runtime

WORKDIR /app/env

COPY --from=deps /app/env/.venv /app/env/.venv
COPY . /app/env

ENV PATH="/app/env/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env/src:/app/env"

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
