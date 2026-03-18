FROM python:3.11-slim-bookworm

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock README.md /app/
COPY src /app/src
COPY manifests /app/manifests
COPY schemas /app/schemas

ENV UV_PROJECT_ENVIRONMENT=/app/.venv
RUN uv venv --python python3.11 /app/.venv \
    && if [ -f uv.lock ]; then \
        uv sync --frozen --no-editable; \
    else \
        uv sync --no-editable; \
    fi

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"

ENTRYPOINT ["openrange"]
CMD ["--help"]
