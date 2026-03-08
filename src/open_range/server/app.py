"""FastAPI application for the OpenRange cybersecurity gymnasium.

If openenv is installed, delegates to ``openenv.core.env_server.create_app``
which provides /health, /reset, /step, /state, /ws, /metadata, /schema
endpoints automatically.

Otherwise falls back to a manual FastAPI app with equivalent HTTP endpoints
plus a WebSocket endpoint at ``/ws`` for persistent sessions.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ValidationError

from open_range.server.console import clear_history, console_router, record_action
from open_range.server.environment import RangeEnvironment
from open_range.server.models import RangeAction, RangeObservation, RangeState

logger = logging.getLogger(__name__)

_APP_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Try the OpenEnv app factory first
# ---------------------------------------------------------------------------


def _try_openenv_app() -> FastAPI | None:
    """Attempt to create the app via openenv.create_app.

    Returns None if openenv is not installed or the import fails.
    """
    try:
        from openenv.core.env_server import create_app

        openenv_app = create_app(
            RangeEnvironment,
            RangeAction,
            RangeObservation,
            env_name="open_range",
        )
        openenv_app.include_router(console_router)
        return openenv_app
    except ImportError:
        logger.info("openenv not installed -- using standalone FastAPI app")
        return None
    except Exception as exc:
        logger.warning("openenv create_app failed (%s) -- falling back", exc)
        return None


# ---------------------------------------------------------------------------
# Standalone FastAPI fallback
# ---------------------------------------------------------------------------


class ResetRequest(BaseModel):
    seed: int | None = None
    episode_id: str | None = None


def _create_standalone_app() -> FastAPI:
    """Build a FastAPI app that mirrors the OpenEnv endpoint contract.

    Endpoints
    ---------
    GET  /health    -- liveness check
    GET  /metadata  -- environment metadata
    GET  /schema    -- JSON schemas for action, observation, state
    POST /reset     -- reset environment, returns initial observation
    POST /step      -- execute an action, returns observation + reward + done
    GET  /state     -- current episode state
    WS   /ws        -- persistent WebSocket session (JSON messages)
    """

    app = FastAPI(
        title="OpenRange",
        description="Multi-agent cybersecurity gymnasium",
        version=_APP_VERSION,
    )

    # Shared environment instance for HTTP endpoints.
    # Each WebSocket session creates its own isolated instance.
    env = RangeEnvironment()

    # Store env on app.state so the console router can access it
    app.state.env = env

    # Include the operator console router
    app.include_router(console_router)

    # ---------------------------------------------------------------
    # HTTP endpoints
    # ---------------------------------------------------------------

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metadata")
    async def metadata() -> dict[str, Any]:
        return {
            "name": "open_range",
            "version": _APP_VERSION,
            "description": "Multi-agent cybersecurity gymnasium built on OpenEnv",
            "supports_concurrent_sessions": False,
        }

    @app.get("/schema")
    async def schema() -> dict[str, Any]:
        return {
            "action": RangeAction.model_json_schema(),
            "observation": RangeObservation.model_json_schema(),
            "state": RangeState.model_json_schema(),
        }

    @app.post("/reset")
    async def reset(req: ResetRequest | None = None) -> dict[str, Any]:
        req = req or ResetRequest()
        clear_history()
        obs = env.reset(seed=req.seed, episode_id=req.episode_id)
        return {"observation": obs.model_dump()}

    @app.post("/step")
    async def step(action: RangeAction) -> dict[str, Any]:
        import time as _time

        obs = env.step(action)
        record_action({
            "step": env.state.step_count,
            "command": action.command,
            "mode": action.mode,
            "time": _time.time(),
        })
        return {
            "observation": obs.model_dump(),
            "reward": obs.reward,
            "done": obs.done,
        }

    @app.get("/state")
    async def get_state() -> dict[str, Any]:
        return env.state.model_dump()

    # ---------------------------------------------------------------
    # WebSocket endpoint
    # ---------------------------------------------------------------

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket) -> None:
        """Persistent WebSocket session with per-connection environment.

        Clients send JSON messages with a ``type`` field:

        * ``{"type": "reset"}``                        -- reset the environment
        * ``{"type": "reset", "seed": 42, "episode_id": "ep1"}``
        * ``{"type": "step", "command": "...", "mode": "red"}``
        * ``{"type": "state"}``                        -- get current state

        The server responds with JSON containing at minimum a ``type``
        field (``"observation"``, ``"state"``, or ``"error"``).
        """
        await websocket.accept()

        # Each WebSocket session gets its own environment instance
        ws_env = RangeEnvironment()

        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await websocket.send_json(
                        {"type": "error", "detail": "Invalid JSON"}
                    )
                    continue

                msg_type = msg.get("type", "")

                if msg_type == "reset":
                    seed = msg.get("seed")
                    episode_id = msg.get("episode_id")
                    obs = ws_env.reset(seed=seed, episode_id=episode_id)
                    await websocket.send_json({
                        "type": "observation",
                        "observation": obs.model_dump(),
                    })

                elif msg_type == "step":
                    try:
                        action = RangeAction(
                            command=msg.get("command", ""),
                            mode=msg.get("mode", "red"),
                        )
                    except ValidationError as ve:
                        await websocket.send_json({
                            "type": "error",
                            "detail": str(ve),
                        })
                        continue

                    obs = ws_env.step(action)
                    await websocket.send_json({
                        "type": "observation",
                        "observation": obs.model_dump(),
                        "reward": obs.reward,
                        "done": obs.done,
                    })

                elif msg_type == "state":
                    await websocket.send_json({
                        "type": "state",
                        "state": ws_env.state.model_dump(),
                    })

                else:
                    await websocket.send_json({
                        "type": "error",
                        "detail": f"Unknown message type: {msg_type!r}",
                    })

        except WebSocketDisconnect:
            logger.debug("WebSocket client disconnected")

    return app


# ---------------------------------------------------------------------------
# Module-level app instance (used by uvicorn)
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Create the OpenRange FastAPI application.

    Tries openenv's create_app first; falls back to standalone.
    """
    openenv_app = _try_openenv_app()
    if openenv_app is not None:
        return openenv_app
    return _create_standalone_app()


app = create_app()
