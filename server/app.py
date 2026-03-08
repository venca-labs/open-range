"""OpenEnv app entrypoint expected by ``openenv.yaml``."""

from __future__ import annotations

from open_range.server.app import app, create_app

__all__ = ["app", "create_app"]


def main() -> None:
    """Run the repository-level server entrypoint via uvicorn."""
    import uvicorn

    uvicorn.run("server.app:app", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
