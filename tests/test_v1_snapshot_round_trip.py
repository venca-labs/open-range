"""v1 snapshot round-trip tests.

A v1 build produces a multi-node-type ``WorldGraph`` (10+ node types,
12 edge types) plus ``feasibility_checks`` / ``episode_checks`` /
codegen runtime artifacts. This file confirms the snapshot survives
``as_dict`` → ``from_mapping`` and the rebuilt snapshot still grades
correctly.
"""

from __future__ import annotations

import json

from openrange.core.builder import build
from openrange.core.snapshot import Snapshot

V1_MANIFEST = {
    "pack": {"id": "cyber.webapp", "source": {"kind": "builtin"}},
    "mode": "simulation",
    "world": {},
}


def test_v1_snapshot_round_trips_through_as_dict() -> None:
    snapshot = build(V1_MANIFEST)
    payload = snapshot.as_dict()

    # Verify the dict serializes through json (catches MappingProxy /
    # tuple leaks that break persistence).
    serialized = json.dumps(payload, sort_keys=True, default=str)
    parsed = json.loads(serialized)

    rebuilt = Snapshot.from_mapping(parsed)

    # Same id, same shape.
    assert rebuilt.id == snapshot.id
    assert rebuilt.manifest.pack.id == snapshot.manifest.pack.id
    assert len(rebuilt.world_graph.nodes) == len(snapshot.world_graph.nodes)
    assert len(rebuilt.world_graph.edges) == len(snapshot.world_graph.edges)


def test_v1_snapshot_world_graph_node_types_preserved() -> None:
    snapshot = build(V1_MANIFEST)
    rebuilt = Snapshot.from_mapping(snapshot.as_dict())
    types_before = sorted(n.type for n in snapshot.world_graph.nodes)
    types_after = sorted(n.type for n in rebuilt.world_graph.nodes)
    assert types_before == types_after


def test_v1_snapshot_checks_round_trip() -> None:
    snapshot = build(V1_MANIFEST)
    rebuilt = Snapshot.from_mapping(snapshot.as_dict())
    assert len(rebuilt.feasibility_checks) == len(snapshot.feasibility_checks)
    assert len(rebuilt.episode_checks) == len(snapshot.episode_checks)
    # The verifier source must round-trip exactly so admission can re-run.
    assert rebuilt.episode_checks[0].source == snapshot.episode_checks[0].source


def test_v1_snapshot_runtime_artifacts_preserved() -> None:
    snapshot = build(V1_MANIFEST)
    rebuilt = Snapshot.from_mapping(snapshot.as_dict())
    before = sorted(snapshot.artifacts.keys())
    after = sorted(rebuilt.artifacts.keys())
    assert before == after
    # The generated app.py source must come back byte-for-byte.
    assert snapshot.artifacts["app.py"] == rebuilt.artifacts["app.py"]


def test_v1_snapshot_verifier_resolves_after_round_trip() -> None:
    snapshot = build(V1_MANIFEST)
    rebuilt = Snapshot.from_mapping(snapshot.as_dict())
    flag = next(
        n.attrs["value_ref"]
        for n in rebuilt.world_graph.nodes
        if n.type == "secret" and n.attrs.get("kind") == "flag"
    )
    verifier = rebuilt.verifier(rebuilt.get_tasks()[0].id)
    result = verifier({"result": {"flag": flag}, "world": {"flag": flag}})
    assert result["passed"] is True
