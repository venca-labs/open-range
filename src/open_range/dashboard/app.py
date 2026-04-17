"""FastAPI application for the OpenRange episode dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from open_range.config import EpisodeConfig
from open_range.contracts.runtime import Action, RuntimeEvent
from open_range.dashboard.bridge import EventBridge
from open_range.dashboard.narrator import nim_narrate
from open_range.render.live import KindBackend
from open_range.runtime import OpenRangeRuntime
from open_range.runtime.execution import PodActionBackend
from open_range.runtime.replay import action_for_reference_step
from open_range.sdk import OpenRange
from open_range.store import FileSnapshotStore

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    *,
    store_dir: str = "snapshots",
    snapshot_id: str | None = None,
    validation_profile: str = "graph_only",
    live: bool = False,
    green_branch_backend: str = "npc",
    green_profile: str = "high",
    npc_mode: str = "offline",
    llm_model: str | None = None,
    llm_endpoint: str | None = None,
) -> Any:
    """Create the dashboard FastAPI app wired to a real OpenRange runtime."""
    try:
        from fastapi import FastAPI
        from fastapi.responses import FileResponse, HTMLResponse
        from sse_starlette.sse import EventSourceResponse
    except ImportError as exc:
        raise ImportError(
            "Dashboard requires extra dependencies. "
            "Install with: uv sync --extra dashboard"
        ) from exc

    app = FastAPI(title="OpenRange Dashboard", version="0.1.0")
    bridge = EventBridge()
    store = FileSnapshotStore(store_dir)
    runtime = OpenRangeRuntime(event_sink=bridge.push)
    default_episode_config = EpisodeConfig()

    live_backend = None
    action_backend = None
    if live:
        live_backend = KindBackend()
        action_backend = PodActionBackend()

    env = OpenRange(
        store=store,
        runtime=runtime,
        live_backend=live_backend,
        action_backend=action_backend,
    )

    # ── Shared mutable state ──────────────────────────────────────────────
    _topology: dict[str, Any] = {}
    _episode_running = threading.Event()
    _episode_thread: list[threading.Thread] = []

    def _extract_topology() -> dict[str, Any]:
        """Pull topology from the runtime's active snapshot."""
        rt = env.runtime
        snap = rt._snapshot  # noqa: SLF001
        if snap is None:
            return {"services": [], "edges": [], "zones": []}

        world = snap.world
        services = []
        zone_set: set[str] = set()
        for svc in world.services:
            host = next((h for h in world.hosts if svc.host == h.id), None)
            zone = host.zone if host else "unknown"
            zone_set.add(zone)
            services.append(
                {
                    "id": svc.id,
                    "kind": svc.kind,
                    "host": svc.host,
                    "zone": zone,
                    "ports": list(svc.ports),
                }
            )

        edges = []
        for edge in world.edges:
            edges.append(
                {
                    "source": edge.source,
                    "target": edge.target,
                    "kind": edge.kind,
                }
            )

        users = [
            {
                "id": u.id,
                "role": u.role,
                "department": u.department,
                "email": u.email,
            }
            for u in world.users
        ]

        green_personas = [
            {
                "id": p.id,
                "role": p.role,
                "department": p.department,
                "home_host": p.home_host,
                "awareness": p.awareness,
            }
            for p in world.green_personas
        ]

        return {
            "services": services,
            "edges": edges,
            "zones": sorted(zone_set),
            "users": users,
            "green_personas": green_personas,
        }

    def _run_episode_loop() -> None:
        """Auto-play the episode using reference traces in a background thread.

        Streams ALL runtime events (red, blue, AND green) to the event bridge
        so the frontend receives the full picture of agent activity.
        """
        try:
            while _episode_running.is_set():
                rt = env.runtime
                state = env.state()
                if state.done:
                    bridge.push(
                        RuntimeEvent(
                            id="episode-done",
                            event_type="BenignUserAction",
                            actor="green",
                            time=state.sim_time,
                            source_entity="system",
                            target_entity="episode",
                            malicious=False,
                            detail="Episode complete",
                        )
                    )
                    _episode_running.clear()
                    break

                try:
                    decision = env.next_decision()
                except RuntimeError as exc:
                    if "done" in str(exc):
                        continue
                    raise

                if rt._snapshot is None:
                    break

                # ── Pick the next action from reference traces ────────────
                step = rt.reference_step(decision.actor)
                if step is None:
                    action = Action(
                        actor_id=f"agent-{decision.actor}",
                        role=decision.actor,
                        kind="sleep",
                        payload={"seconds": 1.0},
                    )
                else:
                    action = action_for_reference_step(
                        rt._snapshot, decision.actor, step
                    )

                env.act(decision.actor, action)

                # Pace the loop so events arrive visually spaced out.
                time.sleep(0.8)

        except Exception:
            logger.exception("Episode loop error")
            _episode_running.clear()

    # ── Routes ────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index():
        html_path = _STATIC_DIR / "index.html"
        return FileResponse(html_path, media_type="text/html")

    @app.get("/api/topology")
    async def topology():
        return _topology or _extract_topology()

    @app.get("/api/state")
    async def state():
        try:
            s = env.state()
            return s.model_dump(mode="json")
        except Exception:
            return {"error": "no active episode"}

    @app.get("/api/events/stream")
    async def event_stream():
        async def generate():
            async for event in bridge.subscribe():
                data = event.model_dump(mode="json")
                yield {"event": "runtime_event", "data": json.dumps(data)}

        return EventSourceResponse(generate())

    @app.post("/api/episode/reset")
    async def reset_episode():
        nonlocal _topology
        _episode_running.clear()
        for t in _episode_thread:
            t.join(timeout=5.0)
        _episode_thread.clear()

        try:
            env.reset(
                snapshot_id,
                EpisodeConfig(
                    mode="joint_pool",
                    green_branch_backend=green_branch_backend,
                    green_profile=green_profile,
                    npc_mode=npc_mode,
                    llm_model=llm_model or default_episode_config.llm_model,
                    llm_endpoint=llm_endpoint or default_episode_config.llm_endpoint,
                ),
            )
        except Exception as exc:
            logger.exception("Reset failed")
            return {"error": str(exc) or "reset failed"}

        _topology = _extract_topology()
        return {
            "status": "ready",
            "snapshot_id": env.active_snapshot_id,
            "topology": _topology,
        }

    @app.post("/api/episode/play")
    async def play_episode():
        if _episode_running.is_set():
            return {"status": "already running"}
        _episode_running.set()
        t = threading.Thread(target=_run_episode_loop, daemon=True)
        _episode_thread.append(t)
        t.start()
        return {"status": "playing"}

    @app.post("/api/episode/pause")
    async def pause_episode():
        _episode_running.clear()
        return {"status": "paused"}

    @app.get("/api/narrate")
    async def narrate():
        events = bridge.snapshot_buffer()
        if not events:
            return {"narration": "The simulation is quiet... waiting for activity."}
        text = await nim_narrate(events)
        return {"narration": text}

    @app.get("/api/narrate/stream")
    async def narrate_stream():
        async def generate():
            last_count = 0
            while True:
                events = bridge.snapshot_buffer()
                if len(events) > last_count:
                    last_count = len(events)
                    text = await nim_narrate(events)
                    yield {"event": "narration", "data": json.dumps({"text": text})}
                await asyncio.sleep(5.0)

        return EventSourceResponse(generate())

    return app
