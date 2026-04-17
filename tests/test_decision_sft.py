from __future__ import annotations

from open_range.contracts.runtime import Action, Observation
from open_range.training.data import TraceLineage
from open_range.training.decision_sft import (
    build_decision_prompt,
    render_action_completion,
    system_prompt_for_role,
)


def test_decision_prompt_and_completion_are_structured() -> None:
    action = Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-web", "path": "/search", "query": {"q": "admin"}},
    )
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
        weaknesses=(),
        benchmark_tags=("cve_bench",),
        trace_source="runtime",
        action_source="reference_runtime",
        split="train",
        prompt_mode="zero_day",
    )
    completion = render_action_completion(action)

    assert "candidate_actions:" not in prompt
    assert "visible_events:" in prompt
    assert "observation_stdout=" in prompt
    assert "last_stdout=" not in prompt
    assert "prompt_mode=" not in prompt
    assert "snapshot_id=" not in prompt
    assert "benchmark_tags=" not in prompt
    assert "weaknesses:" not in prompt
    assert '"operation": "http_request"' in completion
    assert '"path": "/search"' in completion
    system_prompt = system_prompt_for_role("red")
    assert "OpenRange" not in system_prompt
    assert "red operator" not in system_prompt
    assert "authorized penetration test" in system_prompt


def test_decision_prompt_can_optionally_include_hidden_context() -> None:
    prompt = build_decision_prompt(
        snapshot_id="snap-1",
        world_id="world-1",
        world_hash="hash-1",
        lineage=TraceLineage(root_world_id="world-1", generation=0),
        mode="red_only",
        start_state="clean",
        role="red",
        decision_index=0,
        observation=Observation(actor_id="red", sim_time=0.0, stdout="sim_time=0.00"),
        weaknesses=(),
        benchmark_tags=("cve_bench",),
        trace_source="runtime",
        action_source="reference_runtime",
        split="train",
        prompt_mode="one_day",
        include_hidden_context=True,
    )

    assert "action_source=reference_runtime" in prompt
    assert "benchmark_tags=cve_bench" in prompt
    assert "weaknesses:" in prompt


def test_observation_and_action_result_stay_separate_contracts() -> None:
    from open_range.contracts.runtime import ActionResult

    observation_schema = Observation.model_json_schema()
    result_schema = ActionResult.model_json_schema()

    assert "action" not in observation_schema["properties"]
    assert "emitted_events" not in observation_schema["properties"]
    assert "stdout" in observation_schema["properties"]
    assert "action" in result_schema["properties"]
    assert "emitted_events" in result_schema["properties"]
