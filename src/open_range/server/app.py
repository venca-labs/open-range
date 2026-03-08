"""FastAPI application for OpenRange."""

from __future__ import annotations

import inspect
import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def _extract_openenv_server(fastapp: FastAPI) -> object | None:
    """Best-effort extraction of OpenEnv's HTTPEnvServer from route closure."""
    for route in fastapp.router.routes:
        if getattr(route, "path", None) != "/ws":
            continue
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        try:
            closure = inspect.getclosurevars(endpoint)
        except Exception:
            continue
        server = closure.nonlocals.get("self")
        if server is not None and hasattr(server, "active_sessions"):
            return server
    return None


def create_app() -> FastAPI:
    """Create the OpenRange app through the canonical OpenEnv factory."""
    from openenv.core.env_server import create_app as create_openenv_app

    from open_range.models import RangeAction, RangeObservation
    from open_range.server.environment import RangeEnvironment

    runtime = None
    runtime_enabled = os.getenv("OPENRANGE_ENABLE_MANAGED_RUNTIME", "").lower() in {
        "1",
        "true",
        "yes",
    } or bool(os.getenv("OPENRANGE_RUNTIME_MANIFEST"))
    if runtime_enabled:
        from open_range.server.runtime import ManagedSnapshotRuntime

        runtime = ManagedSnapshotRuntime.from_env()

    def env_factory() -> RangeEnvironment:
        return RangeEnvironment(runtime=runtime)

    fastapp = create_openenv_app(
        env_factory,
        RangeAction,
        RangeObservation,
        env_name="open_range",
    )
    openenv_server = _extract_openenv_server(fastapp)
    if openenv_server is not None:
        fastapp.state.openenv_server = openenv_server

    # Mount custom Gradio dashboard at /web if gradio is available
    try:
        import gradio as gr
        from open_range.server.gradio_ui import build_openrange_gradio_app

        blocks = build_openrange_gradio_app(
            web_manager=None,
            action_fields=[],
            metadata=None,
            is_chat_env=False,
            title="OpenRange",
            quick_start_md="",
        )
        fastapp = gr.mount_gradio_app(fastapp, blocks, path="/web")
    except Exception:
        pass  # Gradio is optional

    fastapp.state.env = env_factory()
    if runtime is not None:
        fastapp.state.runtime = runtime
        # NOTE: Do NOT register runtime.start() as a startup event — it
        # synchronously generates snapshots which blocks the health check on
        # resource-constrained hardware (HF Spaces cpu-basic).  The runtime
        # lazy-starts on the first acquire_snapshot() call (triggered by reset()).
        fastapp.add_event_handler("shutdown", runtime.stop)

    try:
        from open_range.server.console import console_router
        fastapp.include_router(console_router)
    except Exception:
        pass  # Console router is optional

    return fastapp


def main() -> None:
    """Run the installed package entrypoint via uvicorn."""
    import uvicorn
    uvicorn.run("open_range.server.app:app", host="0.0.0.0", port=8000)


app = create_app()


if __name__ == "__main__":
    main()
