"""Shared pytest configuration."""

from __future__ import annotations

import os
from pathlib import Path


def pytest_configure(config):
    """Load tests/.env into the process environment before any tests run."""
    env_file = Path(__file__).parent.parent / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key:
            os.environ[key] = value
