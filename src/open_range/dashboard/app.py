"""FastAPI application for the OpenRange episode dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
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
    live: bool = False,
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

    live_backend = None
    action_backend = None
    if live:
        from open_range.cluster import KindBackend
        from open_range.execution import PodActionBackend
        live_backend = KindBackend()
        action_backend = PodActionBackend()

    env = OpenRange(
        store=store,
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

        return {
            "services": services,
            "edges": edges,
            "zones": sorted(zone_set),
            "users": users,
        }

    def _run_episode_loop() -> None:
        """Auto-play the episode using reference traces in a background thread.

        Streams ALL runtime events (red, blue, AND green) to the event bridge
        so the frontend receives the full picture of agent activity.
        """
        from open_range.probe_planner import (
            runtime_action as reference_runtime_action,
        )
        from open_range.runtime_types import Action

        try:
            # Track which events we've already pushed to the bridge.
            # The runtime appends every event (including green routine
            # events generated during _advance_time) to rt._events.
            pushed_event_ids: set[str] = set()

            while _episode_running.is_set():
                rt = env.runtime

                # ── Flush any new events the runtime generated internally ──
                # Green routine events and reactive events are created during
                # _advance_time → _drain_green → _act_green. They live in
                # rt._events but are NOT returned via act().emitted_events.
                if rt and hasattr(rt, "_events"):
                    for ev in rt._events:
                        if ev.id not in pushed_event_ids:
                            bridge.push(ev)
                            pushed_event_ids.add(ev.id)

                state = env.state()
                if state.done:
                    bridge.push(
                        RuntimeEvent(
                            id="episode-done",
                            event_type="EpisodeComplete",
                            actor="green",
                            time=state.sim_time,
                            source_entity="system",
                            target_entity="episode",
                            malicious=False,
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

                # Flush green events generated during next_decision's
                # internal _advance_until_external_decision call.
                if rt and hasattr(rt, "_events"):
                    for ev in rt._events:
                        if ev.id not in pushed_event_ids:
                            bridge.push(ev)
                            pushed_event_ids.add(ev.id)

                if rt._snapshot is None:
                    break

                # ── Pick the next action from reference traces ────────────
                ref_traces = (
                    rt._snapshot.reference_bundle.reference_attack_traces
                    if decision.actor == "red"
                    else rt._snapshot.reference_bundle.reference_defense_traces
                )
                idx_attr = (
                    "_reference_attack_index"
                    if decision.actor == "red"
                    else "_reference_defense_index"
                )
                idx = getattr(rt, idx_attr, 0)

                if (
                    ref_traces
                    and idx < len(ref_traces)
                    and idx < len(ref_traces[0].steps)
                ):
                    ref_action = ref_traces[0].steps[idx]
                    action = reference_runtime_action(
                        actor=decision.actor, step=ref_action
                    )
                    setattr(rt, idx_attr, idx + 1)
                else:
                    action = Action(
                        actor_id=f"agent-{decision.actor}",
                        role=decision.actor,
                        kind="sleep",
                        payload={"seconds": 1.0},
                    )

                result = env.act(decision.actor, action)

                # Push newly emitted events from act()
                for ev in result.emitted_events:
                    if ev.id not in pushed_event_ids:
                        bridge.push(ev)
                        pushed_event_ids.add(ev.id)

                # Pace the loop so events arrive visually spaced out.
                time.sleep(1.5)

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
                    green_branch_backend="npc",
                    green_profile="high",
                ),
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
