"""DashboardView: aggregates snapshot data and event history for the UI."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from openrange.core import ActorTurn, Snapshot
from openrange.core.snapshot import json_safe
from openrange.dashboard.events import (
    DashboardEvent,
    EventBridge,
    fallback_narrate,
    read_dashboard_events,
    read_dashboard_state,
    write_dashboard_state,
)
from openrange.dashboard.summaries import (
    activity_summary,
    actor_summaries,
    health_summary,
)
from openrange.dashboard.topology import (
    empty_runtime_topology,
    normalized_runtime_topology,
    public_world,
    stored_entrypoints,
    stored_missions,
)


class DashboardView:
    def __init__(
        self,
        snapshot: Snapshot | None = None,
        *,
        bridge: EventBridge | None = None,
        event_log_path: str | Path | None = None,
        state_path: str | Path | None = None,
        reset_artifacts: bool = True,
    ) -> None:
        self.snapshot = snapshot
        self.bridge = bridge or EventBridge()
        self._running = False
        self._lock = threading.Lock()
        self._event_log_path = (
            None if event_log_path is None else Path(event_log_path)
        )
        self._state_path = None if state_path is None else Path(state_path)
        self._stored_dashboard = (
            {}
            if self._state_path is None or reset_artifacts
            else read_dashboard_state(self._state_path)
        )
        if self._event_log_path is not None:
            self._event_log_path.parent.mkdir(parents=True, exist_ok=True)
            if reset_artifacts or not self._event_log_path.exists():
                self._event_log_path.write_text("", encoding="utf-8")
            else:
                for event in read_dashboard_events(self._event_log_path):
                    self.bridge.push(event)
        self._event_count = len(self.bridge.snapshot_buffer())
        if self._state_path is not None:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_state(self._state_path)

    def topology(self) -> Mapping[str, object]:
        if self.snapshot is None:
            stored = self._stored_section("topology")
            if stored:
                return stored
            return {
                "snapshot_id": None,
                "world": {},
                "tasks": [],
                "artifact_paths": [],
                **empty_runtime_topology(),
            }
        runtime_topology = normalized_runtime_topology(self.snapshot)
        return {
            "snapshot_id": self.snapshot.id,
            "world": public_world(self.snapshot.world),
            "tasks": [task.as_dict() for task in self.snapshot.tasks],
            "artifact_paths": sorted(self.snapshot.artifacts),
            **runtime_topology,
        }

    def lineage(self) -> Mapping[str, object]:
        if self.snapshot is None:
            stored = self._stored_section("lineage")
            if stored:
                return stored
            return {
                "snapshot_id": None,
                "admission": None,
                "nodes": [],
            }
        return {
            "snapshot_id": self.snapshot.id,
            "admission": self.snapshot.admission.as_dict(),
            "nodes": [node.as_dict() for node in self.snapshot.lineage],
        }

    def state(self) -> Mapping[str, object]:
        events = [event.as_dict() for event in self.bridge.snapshot_buffer()]
        turn_count = sum(1 for event in events if event["type"] == "env_turn")
        return {
            "running": self._running,
            "status": self._status(),
            "snapshot_id": self._snapshot_id(),
            "event_count": len(events),
            "turn_count": turn_count,
            "latest_event": None if not events else events[-1],
            "activity_summary": activity_summary(events),
            "health": health_summary(events),
            "events": events,
        }

    def _status(self) -> str:
        if self.snapshot is None and self._snapshot_id() is None:
            return "waiting_for_snapshot"
        if self._running:
            return "playing"
        return "paused"

    def reset(self, snapshot: Snapshot | None = None) -> Mapping[str, object]:
        if snapshot is not None:
            self.snapshot = snapshot
        self._running = False
        if self.snapshot is None:
            result = {
                "status": "waiting_for_snapshot",
                "snapshot_id": None,
                "topology": self.topology(),
            }
        else:
            result = {
                "status": "ready",
                "snapshot_id": self.snapshot.id,
                "topology": self.topology(),
            }
        self._write_configured_state()
        return result

    def play(self) -> Mapping[str, object]:
        if self._running:
            return {"status": "already running"}
        self._running = True
        self._write_configured_state()
        return {"status": "playing"}

    def pause(self) -> Mapping[str, object]:
        self._running = False
        self._write_configured_state()
        return {"status": "paused"}

    def record_event(
        self,
        event_type: str,
        *,
        actor: str,
        target: str,
        data: Mapping[str, object] | None = None,
    ) -> DashboardEvent:
        with self._lock:
            self._event_count += 1
            event = DashboardEvent(
                f"{self._event_count}:{event_type}",
                event_type,
                actor,
                target,
                float(self._event_count - 1),
                MappingProxyType(dict(data or {})),
            )
            self.bridge.push(event)
            self._write_event(event)
        return event

    def record_turn(self, turn: ActorTurn) -> DashboardEvent:
        return self.record_event(
            "env_turn",
            actor=turn.actor_id,
            target=turn.target,
            data=turn.as_dict(),
        )

    def turns(self, task_id: str | None = None) -> list[dict[str, object]]:
        turns = [
            dict(event.data)
            for event in self.bridge.snapshot_buffer()
            if event.type == "env_turn"
        ]
        if task_id is None:
            return turns
        return [turn for turn in turns if turn.get("task_id") == task_id]

    def builder_steps(self) -> list[dict[str, object]]:
        return [
            dict(event.data)
            for event in self.bridge.snapshot_buffer()
            if event.type == "builder_step"
        ]

    def inspect(self) -> Mapping[str, object]:
        return {
            "briefing": self.briefing(),
            "topology": self.topology(),
            "lineage": self.lineage(),
            "state": self.state(),
            "actors": self.actors(),
            "turns": self.turns(),
            "builder": {"steps": self.builder_steps()},
            "narration": self.narration(),
        }

    def actors(self) -> list[dict[str, object]]:
        return actor_summaries(
            [event.as_dict() for event in self.bridge.snapshot_buffer()],
        )

    def briefing(self) -> Mapping[str, object]:
        if self.snapshot is None:
            topology = self.topology()
            snapshot_id = topology.get("snapshot_id")
            world = topology.get("world")
            tasks = topology.get("tasks")
            if isinstance(snapshot_id, str) and isinstance(world, Mapping):
                task_rows = tasks if isinstance(tasks, list) else []
                return {
                    "snapshot_id": snapshot_id,
                    "title": str(world.get("title", "")),
                    "goal": str(world.get("goal", "")),
                    "entrypoints": stored_entrypoints(task_rows),
                    "missions": stored_missions(task_rows),
                }
            return {
                "snapshot_id": None,
                "title": "",
                "goal": "",
                "entrypoints": [],
                "missions": [],
            }
        return {
            "snapshot_id": self.snapshot.id,
            "title": str(self.snapshot.world.get("title", "")),
            "goal": str(self.snapshot.world.get("goal", "")),
            "entrypoints": [
                {
                    "task_id": task.id,
                    "kind": entrypoint.kind,
                    "target": entrypoint.target,
                }
                for task in self.snapshot.tasks
                for entrypoint in task.entrypoints
            ],
            "missions": [
                {"task_id": task.id, "instruction": task.instruction}
                for task in self.snapshot.tasks
            ],
        }

    def narration(self) -> Mapping[str, object]:
        return {"narration": fallback_narrate(self.bridge.snapshot_buffer())}

    def _write_event(self, event: DashboardEvent) -> None:
        if self._event_log_path is not None:
            with self._event_log_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(json_safe(event.as_dict()), sort_keys=True) + "\n",
                )
        self._write_configured_state()

    def _write_configured_state(self) -> None:
        if self._state_path is not None:
            self._write_state(self._state_path)

    def _write_state(self, state_path: Path) -> None:
        write_dashboard_state(state_path, self.bridge.snapshot_buffer(), self)

    def _stored_section(self, key: str) -> Mapping[str, object]:
        section = self._stored_dashboard.get(key)
        if isinstance(section, Mapping):
            return section
        return {}

    def _snapshot_id(self) -> str | None:
        if self.snapshot is not None:
            return self.snapshot.id
        topology = self._stored_section("topology")
        snapshot_id = topology.get("snapshot_id")
        return snapshot_id if isinstance(snapshot_id, str) else None
