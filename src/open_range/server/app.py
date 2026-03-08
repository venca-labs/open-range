"""FastAPI application wired through the OpenEnv app factory."""

from __future__ import annotations

from fastapi import FastAPI
from openenv.core.env_server import create_app as create_openenv_app

from open_range.server.console import console_router
from open_range.server.environment import RangeEnvironment
from open_range.server.models import RangeAction, RangeObservation
from open_range.server.runtime import ManagedSnapshotRuntime


def create_app() -> FastAPI:
    """Create the OpenRange app using the standard OpenEnv contract."""
    runtime = ManagedSnapshotRuntime.from_env()

    def env_factory() -> RangeEnvironment:
        return RangeEnvironment(runtime=runtime)

    app = create_openenv_app(
        env_factory,
        RangeAction,
        RangeObservation,
        env_name="open_range",
    )
    app.state.env = env_factory()
    app.state.runtime = runtime
    app.add_event_handler("startup", runtime.start)
    app.add_event_handler("shutdown", runtime.stop)
    app.include_router(console_router)
    return app


def main() -> None:
    """Run the installed package entrypoint via uvicorn."""
    import uvicorn

    uvicorn.run("open_range.server.app:app", host="0.0.0.0", port=8000)


app = create_app()

if __name__ == "__main__":
    main()
