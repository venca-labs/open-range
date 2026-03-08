"""FastAPI application for OpenRange."""

from __future__ import annotations

import json
import inspect
import logging
import os
from types import SimpleNamespace
from pathlib import Path

from fastapi import FastAPI

logger = logging.getLogger(__name__)
_TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_flag(name: str, *, default: bool = False) -> bool:
    """Parse a boolean-like environment variable."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in _TRUE_VALUES


def _managed_runtime_enabled() -> bool:
    """Managed runtime is on by default unless explicitly disabled."""
    if _env_flag("OPENRANGE_DISABLE_MANAGED_RUNTIME", default=False):
        return False

    raw = os.getenv("OPENRANGE_ENABLE_MANAGED_RUNTIME")
    if raw is None or not raw.strip():
        return True
    return raw.strip().lower() in _TRUE_VALUES


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

    from open_range.protocols import SnapshotSpec
    from open_range.models import RangeAction, RangeObservation
    from open_range.server.environment import RangeEnvironment

    default_snapshot = None
    snapshot_env = os.getenv("OPENRANGE_RUNTIME_SNAPSHOT", "").strip()
    if snapshot_env:
        snapshot_path = Path(snapshot_env)
        if snapshot_path.exists():
            payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
            default_snapshot = SnapshotSpec.model_validate(payload)
            logger.info("OpenRange app using fixed runtime snapshot from %s", snapshot_path)
        else:
            logger.warning(
                "OPENRANGE_RUNTIME_SNAPSHOT points to missing file: %s. Falling back to managed runtime selection.",
                snapshot_path,
            )

    mock_mode = _env_flag("OPENRANGE_MOCK", default=False)

    runtime = None
    if _managed_runtime_enabled() and not mock_mode:
        from open_range.server.runtime import ManagedSnapshotRuntime

        runtime = ManagedSnapshotRuntime.from_env()

    def env_factory() -> RangeEnvironment:
        execution_mode = os.getenv(
            "OPENRANGE_EXECUTION_MODE",
            "subprocess" if default_snapshot is not None else "auto",
        )
        return RangeEnvironment(
            runtime=runtime,
            docker_available=False if mock_mode else None,
            default_snapshot=default_snapshot,
            execution_mode=execution_mode,
        )

    fastapp = create_openenv_app(
        env_factory,
        RangeAction,
        RangeObservation,
        env_name="open_range",
    )
    openenv_server = _extract_openenv_server(fastapp)
    if openenv_server is not None:
        fastapp.state.openenv_server = openenv_server

    # Mount custom Gradio dashboard at /dashboard (separate from the OpenEnv
    # Playground at /web which provides interactive reset/step via the
    # WebInterfaceManager's persistent environment instance).
    try:
        from open_range.server.console import clear_episode

        clear_episode()
    except Exception:
        pass

    fastapp.state.env = env_factory()
    if not hasattr(fastapp.state, "openenv_server"):
        fastapp.state.openenv_server = SimpleNamespace(
            _env_factory=env_factory,
            _sessions={},
            _session_info={},
            active_sessions=0,
        )
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
