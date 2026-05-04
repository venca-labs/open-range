"""End-to-end EpisodeService tests against the v1 cyber pack.

Exercises the full pipeline: build a v1 snapshot → start_episode →
NPCs run alongside an external GET → submit a result → stop_episode →
verifier passes. Uses scripted requests in lieu of an LLM-driven agent.
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import cast

import openrange as OR
from openrange.core.builder import build
from openrange.core.episode import EpisodeService

V1_MANIFEST = {
    "pack": {"id": "cyber.webapp", "source": {"kind": "builtin"}},
    "mode": "simulation",
    "world": {},
    "runtime": {"tick": {"mode": "manual"}},
}


def _flag_value(snapshot: OR.Snapshot) -> str:
    assert snapshot.world_graph is not None
    for node in snapshot.world_graph.nodes:
        if node.type == "secret" and node.attrs.get("kind") == "flag":
            return str(node.attrs["value_ref"])
    raise AssertionError("snapshot has no flag secret")


def test_v1_episode_round_trip_with_scripted_solve(tmp_path: Path) -> None:
    """Build → start episode → agent hits HTTP → submits flag → verifier passes."""
    snapshot = build(V1_MANIFEST)
    flag = _flag_value(snapshot)

    service = EpisodeService(tmp_path / "runs")
    handle = service.start_episode(snapshot)
    try:
        # Scripted "agent": probe the service (so the request log records an
        # interaction; required by validate_public_interface_interaction)…
        base_url = service.base_url(handle)
        with urllib.request.urlopen(f"{base_url}/", timeout=2) as response:
            assert response.status == 200
        with urllib.request.urlopen(f"{base_url}/openapi.json", timeout=2) as response:
            assert response.status == 200
        # …then write the flag to the result file (in a real episode an
        # LLM agent would derive this via exploit; we shortcut for the
        # integration smoke test).
        agent_root = service.agent_root(handle)
        (agent_root / "result.json").write_text(
            json.dumps({"flag": flag}),
            encoding="utf-8",
        )
    finally:
        report = service.stop_episode(handle)

    assert report.verifier_result is not None
    assert report.verifier_result["passed"] is True, dict(report.verifier_result)
    result = cast("dict[str, object]", report.final_state["result"])
    assert result["flag"] == flag


def test_v1_episode_serves_openapi_discovery(tmp_path: Path) -> None:
    """The realized app exposes the discovery payload at /openapi.json."""
    snapshot = build(V1_MANIFEST)
    service = EpisodeService(tmp_path / "runs")
    handle = service.start_episode(snapshot)
    try:
        base_url = service.base_url(handle)
        with urllib.request.urlopen(f"{base_url}/openapi.json", timeout=2) as response:
            payload = json.loads(response.read().decode())
        assert "services" in payload
        assert any(svc["kind"] == "web" for svc in payload["services"])
    finally:
        service.stop_episode(handle)


def test_v1_episode_runs_npcs_during_ticks(tmp_path: Path) -> None:
    """Manifest NPCs make real HTTP requests on tick — verify via request log."""
    manifest = {
        **V1_MANIFEST,
        "npc": [
            {
                "type": "cyber.browsing_user",
                "count": 1,
                "config": {"cadence_ticks": 1, "paths": ["/openapi.json"]},
            },
        ],
    }
    snapshot = build(manifest)
    service = EpisodeService(tmp_path / "runs")
    handle = service.start_episode(snapshot)
    try:
        # Manual tick: each call advances NPCs and captures requests.
        service.tick(handle)
        service.tick(handle)
        service.tick(handle)
        # Allow the server's log to flush.
        time.sleep(0.05)
        # Stop with a fake result so the verifier can run.
        agent_root = service.agent_root(handle)
        (agent_root / "result.json").write_text(
            json.dumps({"flag": _flag_value(snapshot)}),
            encoding="utf-8",
        )
    finally:
        report = service.stop_episode(handle)
    requests = cast("list[dict[str, object]]", report.final_state["requests"])
    npc_paths = [str(row.get("path", "")) for row in requests]
    assert any("/openapi.json" in p for p in npc_paths), npc_paths


def test_v1_episode_unknown_npc_type_fails_cleanly(tmp_path: Path) -> None:
    """Bad manifest NPC type raises during start_episode, not silently."""
    import pytest

    from openrange.core.npc import NPCError

    manifest = {
        **V1_MANIFEST,
        "npc": [{"type": "does.not.exist"}],
    }
    snapshot = build(manifest)
    service = EpisodeService(tmp_path / "runs")
    with pytest.raises(NPCError, match="unknown NPC"):
        service.start_episode(snapshot)


def test_v1_episode_injects_llm_into_npc_context(tmp_path: Path) -> None:
    """LLM-opt-in NPCs receive an ``llm`` key in start() context.

    Plain NPCs do not. Verifies the runtime honors ``requires_llm``
    on a per-NPC basis and threads ``EpisodeService.npc_llm_model``
    through.
    """
    from collections.abc import Mapping
    from typing import Any

    from openrange.core.npc import NPC, NPCS, AgentNPC

    seen_contexts: dict[str, Mapping[str, Any]] = {}

    class _RecordingPlainNPC(NPC):
        # Inherits requires_llm = False
        def start(self, context: Mapping[str, Any]) -> None:
            seen_contexts["plain"] = dict(context)

        def step(self, interface: Mapping[str, Any]) -> None: ...

    class _RecordingAgentNPC(AgentNPC):
        # Inherits requires_llm = True
        def start(self, context: Mapping[str, Any]) -> None:
            super().start(context)
            seen_contexts["agent"] = dict(context)

        def _build_tools(self, interface: Mapping[str, Any]) -> tuple[Any, ...]:
            return ()

        def _build_agent(self, tools: Any) -> Any:
            return None  # never invoked — cadence won't matter

    NPCS.register("test.recording_plain", lambda config: _RecordingPlainNPC())
    NPCS.register(
        "test.recording_agent",
        lambda config: _RecordingAgentNPC(system_prompt="x", cadence_ticks=999),
    )
    try:
        manifest = {
            **V1_MANIFEST,
            "npc": [
                {"type": "test.recording_plain"},
                {"type": "test.recording_agent"},
            ],
        }
        snapshot = build(manifest)
        service = EpisodeService(
            tmp_path / "runs",
            npc_llm_model="claude-sonnet-4-20250514",
        )
        handle = service.start_episode(snapshot)
        try:
            base_url = service.base_url(handle)
            with urllib.request.urlopen(f"{base_url}/", timeout=2) as response:
                assert response.status == 200
            (service.agent_root(handle) / "result.json").write_text(
                json.dumps({"flag": _flag_value(snapshot)}),
                encoding="utf-8",
            )
        finally:
            service.stop_episode(handle)
    finally:
        # Best-effort cleanup — NPCRegistry has no public unregister.
        NPCS._factories.pop("test.recording_plain", None)
        NPCS._factories.pop("test.recording_agent", None)

    assert "llm" not in seen_contexts["plain"]
    assert seen_contexts["agent"]["llm"] == "claude-sonnet-4-20250514"


def test_v1_episode_omits_llm_when_runtime_model_unset(tmp_path: Path) -> None:
    """An LLM-opt-in NPC sees ``llm = None`` when the service has no model."""
    from collections.abc import Mapping
    from typing import Any

    from openrange.core.npc import NPCS, AgentNPC

    seen: dict[str, Mapping[str, Any]] = {}

    class _Recording(AgentNPC):
        def start(self, context: Mapping[str, Any]) -> None:
            super().start(context)
            seen["ctx"] = dict(context)

        def _build_tools(self, interface: Mapping[str, Any]) -> tuple[Any, ...]:
            return ()

        def _build_agent(self, tools: Any) -> Any:
            return None

    NPCS.register(
        "test.no_llm_runtime",
        lambda config: _Recording(system_prompt="x", cadence_ticks=999),
    )
    try:
        manifest = {**V1_MANIFEST, "npc": [{"type": "test.no_llm_runtime"}]}
        snapshot = build(manifest)
        service = EpisodeService(tmp_path / "runs")  # npc_llm_model defaults to None
        handle = service.start_episode(snapshot)
        try:
            base_url = service.base_url(handle)
            with urllib.request.urlopen(f"{base_url}/", timeout=2) as response:
                assert response.status == 200
            (service.agent_root(handle) / "result.json").write_text(
                json.dumps({"flag": _flag_value(snapshot)}),
                encoding="utf-8",
            )
        finally:
            service.stop_episode(handle)
    finally:
        NPCS._factories.pop("test.no_llm_runtime", None)

    assert "llm" in seen["ctx"]
    assert seen["ctx"]["llm"] is None
