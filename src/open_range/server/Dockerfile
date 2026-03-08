FROM python:3.11-slim

WORKDIR /app

# Install system deps needed by Docker SDK (for controlling range containers)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        docker.io \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY openenv.yaml .

# Install Python dependencies
RUN pip install --no-cache-dir -e .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "open_range.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
