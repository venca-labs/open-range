"""Multi-run discovery + live event-log tailing for the dashboard server.

The dashboard server runs in a separate process from the run that
writes events to ``dashboard.events.jsonl``. The reader-side
``DashboardView`` only reads the file once at construction; without
the per-run tail thread, events appended *after* the view exists
never reach the in-memory bridge that drives the SSE stream. These
tests pin the tail-thread contract.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from openrange.dashboard.events import DashboardEvent
from openrange.dashboard.runs import RunsRegistry


def _make_run_dir(parent: Path, run_id: str) -> Path:
    run = parent / run_id
    run.mkdir(parents=True)
    (run / "dashboard.events.jsonl").write_text("", encoding="utf-8")
    (run / "dashboard.json").write_text("{}", encoding="utf-8")
    return run


def _append_event(events_path: Path, event_id: str) -> None:
    payload = {
        "id": event_id,
        "type": "env_turn",
        "actor": "Alice",
        "target": "office",
        "time": 0.0,
        "data": {"action": {"speak": f"hello-{event_id}"}},
    }
    with events_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def _wait_for_event(
    bridge_snapshot: Callable[[], tuple[DashboardEvent, ...]],
    actor: str,
    speak_marker: str,
    *,
    timeout: float,
) -> bool:
    """Spin until the bridge contains the expected event or times out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snap = bridge_snapshot()
        for event in snap:
            data = event.data if isinstance(event.data, Mapping) else {}
            action = data.get("action") if isinstance(data, Mapping) else None
            if (
                event.actor == actor
                and isinstance(action, Mapping)
                and action.get("speak") == speak_marker
            ):
                return True
        time.sleep(0.05)
    return False


def test_tail_picks_up_events_appended_after_view_created(tmp_path: Path) -> None:
    """The reader's bridge surfaces lines appended after view creation."""
    runs_dir = tmp_path / "runs"
    run = _make_run_dir(runs_dir, "live-run")
    events_path = run / "dashboard.events.jsonl"

    registry = RunsRegistry(runs_dir)
    try:
        view = registry.view_for("live-run")
        assert view is not None

        # File was empty when the view was created; bridge starts empty.
        assert view.bridge.snapshot_buffer() == ()

        # Writer (separate process in production) appends a line.
        _append_event(events_path, "1:env_turn")

        ok = _wait_for_event(
            view.bridge.snapshot_buffer,
            "Alice",
            "hello-1:env_turn",
            timeout=2.0,
        )
        assert ok, (
            "tail thread should have pushed the appended event into the "
            "bridge within 2s"
        )
    finally:
        registry.close()


def test_tail_streams_multiple_appends_in_order(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    run = _make_run_dir(runs_dir, "live-run")
    events_path = run / "dashboard.events.jsonl"

    registry = RunsRegistry(runs_dir)
    try:
        view = registry.view_for("live-run")
        assert view is not None

        for index in range(5):
            _append_event(events_path, f"{index}:env_turn")

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if len(view.bridge.snapshot_buffer()) >= 5:
                break
            time.sleep(0.05)

        events = list(view.bridge.snapshot_buffer())
        assert len(events) == 5
        actors = [event.actor for event in events]
        assert actors == ["Alice"] * 5
        # Order preserved.
        assert [event.id for event in events] == [f"{i}:env_turn" for i in range(5)]
    finally:
        registry.close()


def test_tail_includes_history_then_streams_new(tmp_path: Path) -> None:
    """Pre-existing events load via DashboardView; tail picks up new ones."""
    runs_dir = tmp_path / "runs"
    run = _make_run_dir(runs_dir, "live-run")
    events_path = run / "dashboard.events.jsonl"

    # Two events written BEFORE the view is created — DashboardView's
    # initial read should pick them up.
    _append_event(events_path, "0:env_turn")
    _append_event(events_path, "1:env_turn")

    registry = RunsRegistry(runs_dir)
    try:
        view = registry.view_for("live-run")
        assert view is not None
        # Initial read should have surfaced both pre-existing events.
        history_ids = {event.id for event in view.bridge.snapshot_buffer()}
        assert history_ids == {"0:env_turn", "1:env_turn"}

        # Now append a new event — the tail should add it without
        # double-publishing the historical pair.
        _append_event(events_path, "2:env_turn")

        ok = _wait_for_event(
            view.bridge.snapshot_buffer,
            "Alice",
            "hello-2:env_turn",
            timeout=2.0,
        )
        assert ok

        all_ids = [event.id for event in view.bridge.snapshot_buffer()]
        assert all_ids.count("0:env_turn") == 1
        assert all_ids.count("1:env_turn") == 1
        assert all_ids.count("2:env_turn") == 1
    finally:
        registry.close()


def test_close_stops_tail_threads(tmp_path: Path) -> None:
    """``RunsRegistry.close()`` joins the tail threads cleanly."""
    runs_dir = tmp_path / "runs"
    _make_run_dir(runs_dir, "a")
    _make_run_dir(runs_dir, "b")
    registry = RunsRegistry(runs_dir)
    assert registry.view_for("a") is not None
    assert registry.view_for("b") is not None
    # Just don't hang.
    registry.close()


def test_tail_handles_truncation_gracefully(tmp_path: Path) -> None:
    """If the events file shrinks (truncated / replaced), tail re-reads.

    Real-world writers only append, but a defensive truncation reset
    keeps the tail from stalling if the writer ever rotates. We pause
    long enough between truncate and append for the tail's
    250 ms poll to observe the size-zero state — otherwise the tail
    sees only the post-append size and seeks to a stale offset that
    falls in the middle of the new JSON line.
    """
    runs_dir = tmp_path / "runs"
    run = _make_run_dir(runs_dir, "live-run")
    events_path = run / "dashboard.events.jsonl"

    _append_event(events_path, "0:env_turn")
    registry = RunsRegistry(runs_dir)
    try:
        view = registry.view_for("live-run")
        assert view is not None
        ok = _wait_for_event(
            view.bridge.snapshot_buffer,
            "Alice",
            "hello-0:env_turn",
            timeout=2.0,
        )
        assert ok

        # Truncate, give the tail a poll window to notice (offset → 0),
        # then append fresh.
        events_path.write_text("", encoding="utf-8")
        time.sleep(0.4)
        _append_event(events_path, "fresh:env_turn")
        ok = _wait_for_event(
            view.bridge.snapshot_buffer,
            "Alice",
            "hello-fresh:env_turn",
            timeout=2.0,
        )
        assert ok
    finally:
        registry.close()


def test_tail_ignores_partial_trailing_line(tmp_path: Path) -> None:
    """A half-flushed final line should not be eaten on the next poll."""
    runs_dir = tmp_path / "runs"
    run = _make_run_dir(runs_dir, "live-run")
    events_path = run / "dashboard.events.jsonl"

    registry = RunsRegistry(runs_dir)
    try:
        view = registry.view_for("live-run")
        assert view is not None

        # Write a partial JSON line (no trailing newline yet).
        partial = json.dumps(
            {
                "id": "partial:env_turn",
                "type": "env_turn",
                "actor": "Alice",
                "target": "office",
                "time": 0.0,
                "data": {"action": {"speak": "hello-partial"}},
            },
        )
        events_path.write_text(partial, encoding="utf-8")

        # Wait long enough that the tail has polled and decided to skip.
        time.sleep(0.4)
        assert view.bridge.snapshot_buffer() == ()

        # Complete the line with the trailing newline.
        with events_path.open("a", encoding="utf-8") as handle:
            handle.write("\n")

        ok = _wait_for_event(
            view.bridge.snapshot_buffer,
            "Alice",
            "hello-partial",
            timeout=2.0,
        )
        assert ok

        # And only one DashboardEvent landed for that id.
        ids = [
            event.id
            for event in view.bridge.snapshot_buffer()
            if isinstance(event, DashboardEvent)
        ]
        assert ids.count("partial:env_turn") == 1
    finally:
        registry.close()
