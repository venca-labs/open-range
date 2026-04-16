from __future__ import annotations

from types import SimpleNamespace

from open_range.rewards import RewardEngine
from open_range.runtime_types import Action


def test_red_reward_keeps_tick_cost_and_milestone_bonus():
    engine = RewardEngine()
    action = Action(
        actor_id="red", role="red", kind="api", payload={"target": "svc-web"}
    )
    event = SimpleNamespace(
        event_type="InitialAccess",
        linked_objective_predicates=(),
    )

    reward = engine.on_red_action(action, (event,))

    assert round(reward, 4) == 0.09


def test_red_reward_applies_hallucination_penalty_for_false_claim():
    engine = RewardEngine()
    action = Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-web", "claim_objective": "asset_read(finance_docs)"},
    )

    reward = engine.on_red_action(action, ())

    assert reward == -0.31


def test_red_reward_can_disable_hallucination_penalty_for_false_claim():
    engine = RewardEngine()
    action = Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-web", "claim_objective": "asset_read(finance_docs)"},
    )

    reward = engine.on_red_action(action, (), hallucination_penalty_enabled=False)

    assert reward == -0.01


def test_blue_reward_tracks_valid_detection_and_false_positives():
    engine = RewardEngine()
    valid = SimpleNamespace(id="evt-1")

    assert engine.on_blue_detection(valid) == 0.1
    assert engine.on_blue_detection(valid) == 0.0
    assert engine.on_blue_detection(None) == -0.1


def test_blue_reward_can_disable_false_positive_penalty_and_all_shaping():
    engine = RewardEngine()

    assert engine.on_blue_detection(None, false_positive_penalty_enabled=False) == 0.0
    assert engine.on_blue_detection(None, shaping_enabled=False) == 0.0


def test_blue_containment_reward_is_path_breakage_minus_continuity_loss():
    engine = RewardEngine()

    reward = engine.on_blue_containment(
        target="svc-db",
        path_broken=True,
        continuity_before=1.0,
        continuity_after=0.95,
    )

    assert round(reward, 4) == 0.19
