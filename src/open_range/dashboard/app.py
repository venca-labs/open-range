"""FastAPI application for the OpenRange episode dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path
from typing import Any

from open_range.dashboard.bridge import EventBridge
from open_range.dashboard.narrator import nim_narrate
from open_range.episode_config import EpisodeConfig
from open_range.runtime_types import RuntimeEvent
from open_range.service import OpenRange
from open_range.store import FileSnapshotStore

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    *,
    store_dir: str = "snapshots",
    snapshot_id: str | None = None,
    validation_profile: str = "graph_only",
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
    env = OpenRange(store=store)

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

        return {
            "services": services,
            "edges": edges,
            "zones": sorted(zone_set),
            "users": users,
        }

    def _run_episode_loop() -> None:
        """Auto-play the episode using reference traces in a background thread."""
        try:
            while _episode_running.is_set():
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
                        )
                    )
                    _episode_running.clear()
                    break

                decision = env.next_decision()
                from open_range.probe_planner import (
                    runtime_action as reference_runtime_action,
                )

                rt = env.runtime
                snap = rt._snapshot  # noqa: SLF001
                if snap is None:
                    break

                ref_traces = (
                    snap.reference_attack_traces
                    if decision.actor == "red"
                    else snap.reference_defense_traces
                )
                idx_attr = (
                    "_reference_attack_index"
                    if decision.actor == "red"
                    else "_reference_defense_index"
                )
                idx = getattr(rt, idx_attr, 0)

                if idx < len(ref_traces) and idx < len(ref_traces[0].actions):
                    ref_action = ref_traces[0].actions[idx]
                    action = reference_runtime_action(ref_action, actor=decision.actor)
                    setattr(rt, idx_attr, idx + 1)
                else:
                    from open_range.runtime_types import Action

                    action = Action(
                        actor_id=f"agent-{decision.actor}",
                        role=decision.actor,
                        kind="sleep",
                        payload={"seconds": 1.0},
                    )

                result = env.act(decision.actor, action)
                for ev in result.emitted_events:
                    bridge.push(ev)

                import time

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
                EpisodeConfig(mode="joint_pool"),
            )
        except Exception:
            logger.exception("Reset failed")
            return {"error": "reset failed"}

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
