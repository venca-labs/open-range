"""Auto-evolve demo: build → simulate report → auto_evolve, in a loop.

Demonstrates ``openrange.auto_evolve`` end-to-end without requiring a
real agent backend. Synthetic ``EpisodeReport`` payloads stand in for
agent runs so the curriculum walk is visible in seconds.

Each iteration:
  1. Inspect the current world's vulns and pick one whose endpoint the
     "agent" will hit (simulating a successful exploit).
  2. Construct an ``EpisodeReport`` with that request log + passed=True.
  3. Call ``auto_evolve`` — the cyber pack enumerates mutations,
     ``direction_from_reports`` picks ``harden`` (pass-rate=1.0), and
     the patch corresponding to the exploited kind has the highest
     relevance, so ``evolve()`` is called with that directive.
  4. The new snapshot has one fewer vuln family. Repeat until no vulns
     remain or auto_evolve no-ops.

Run::

    uv run python -m examples.auto_eval

Optional: pass ``--with-llm`` to use Codex for relevance enrichment.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from types import MappingProxyType

import openrange as OR

MANIFEST: dict[str, object] = {
    "world": {"goal": "find the admin flag in a vulnerable webapp"},
    "pack": {"id": "cyber.webapp", "source": {"kind": "builtin"}},
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-steps",
        type=int,
        default=4,
        help="upper bound on auto-evolve iterations",
    )
    parser.add_argument(
        "--with-llm",
        action="store_true",
        help="use Codex backend for relevance enrichment",
    )
    args = parser.parse_args()

    llm: OR.LLMBackend | None = OR.CodexBackend() if args.with_llm else None

    snapshot = OR.build(MANIFEST, llm=llm)
    print(_describe_snapshot(snapshot, label="initial"))

    for step in range(1, args.max_steps + 1):
        vuln_kinds = _vuln_kinds_in_world(snapshot)
        if not vuln_kinds:
            print(f"step {step}: world has no vulns left — curriculum exhausted")
            break

        # Simulate an agent that successfully exploits the first vuln kind.
        target_kind = sorted(vuln_kinds)[0]
        target_path = _first_path_for_kind(snapshot, target_kind)
        report = _synthetic_report(snapshot.id, target_path, hits=8, passed=True)

        evolved = OR.auto_evolve(snapshot, report, llm=llm)
        if evolved.id == snapshot.id:
            print(f"step {step}: auto_evolve was a no-op (no relevant mutation)")
            break

        directive = dict(evolved.lineage[-1].curriculum or {})
        print(
            f"step {step}: agent exploited {target_kind!r} via {target_path!r} "
            f"-> auto_evolve chose {directive}",
        )
        print(_describe_snapshot(evolved, label=f"step {step}"))
        snapshot = evolved

    print()
    print("--- lineage ---")
    for node in snapshot.lineage:
        directive = dict(node.curriculum or {})
        print(f"  {node.id}  parent={node.parent_id or '-'}  curriculum={directive}")


def _describe_snapshot(snapshot: OR.Snapshot, *, label: str) -> str:
    kinds = sorted(_vuln_kinds_in_world(snapshot))
    return f"[{label}] {snapshot.id}  vulns={kinds}"


def _vuln_kinds_in_world(snapshot: OR.Snapshot) -> set[str]:
    graph = snapshot.world_graph
    if graph is None:
        return set()
    return {
        str(n.attrs.get("kind", "")) for n in graph.nodes if n.type == "vulnerability"
    }


def _first_path_for_kind(snapshot: OR.Snapshot, kind: str) -> str:
    """Find an HTTP path on an endpoint that's affected by a vuln of ``kind``."""
    graph = snapshot.world_graph
    assert graph is not None
    vuln_ids = {
        n.id
        for n in graph.nodes
        if n.type == "vulnerability" and n.attrs.get("kind") == kind
    }
    target_ids: set[str] = set()
    for edge in graph.edges:
        if edge.relation == "affects" and edge.source in vuln_ids:
            target_ids.add(edge.target)
    for node in graph.nodes:
        if node.id in target_ids and node.type == "endpoint":
            path = str(node.attrs.get("path", ""))
            if path:
                return path
    return "/"


def _synthetic_report(
    snapshot_id: str,
    path: str,
    *,
    hits: int,
    passed: bool,
) -> OR.EpisodeReport:
    requests: Sequence[dict[str, object]] = [
        {"method": "GET", "path": path, "status": 200} for _ in range(hits)
    ]
    return OR.EpisodeReport(
        snapshot_id=snapshot_id,
        task_id="synthetic",
        final_state=MappingProxyType({"requests": list(requests)}),
        verifier_result=MappingProxyType(
            {"passed": passed, "score": 1.0 if passed else 0.0},
        ),
    )


if __name__ == "__main__":
    main()
