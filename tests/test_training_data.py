from __future__ import annotations

from open_range import (
    Action,
    TraceCandidate,
    TraceLineage,
    build_decision_prompt,
    render_action_text,
    render_candidate_completion,
    system_prompt_for_role,
)
from open_range.runtime_types import Observation


def test_decision_prompt_and_completion_are_structured() -> None:
    action = Action(actor_id="red", role="red", kind="api", payload={"target": "svc-web", "path": "/search", "query": {"q": "admin"}})
    candidate = TraceCandidate(label="teacher", action=action, text=render_action_text(action), selected=True, counterfactual_label="teacher")
    prompt = build_decision_prompt(
        snapshot_id="snap-1",
        world_id="world-1",
        world_hash="hash-1",
        lineage=TraceLineage(root_world_id="world-1", generation=0),
        mode="red_only",
        start_state="clean",
        role="red",
        decision_index=2,
        observation=Observation(actor_id="red", sim_time=1.5, stdout="sim_time=1.50"),
        candidate_actions=(candidate,),
        weaknesses=(),
        benchmark_tags=("cve_bench",),
        trace_source="runtime",
        teacher_source="witness_runtime",
        split="train",
        prompt_mode="zero_day",
    )
    completion = render_candidate_completion(candidate)

    assert "candidate_actions:" in prompt
    assert "[teacher]" in prompt
    assert "benchmark_tags=cve_bench" in prompt
    assert "prompt_mode=zero_day" in prompt
    assert "<choice>teacher</choice>" in completion
    assert "svc-web/search?q=admin" in completion
    assert "Choose exactly one candidate action" in system_prompt_for_role("red")
