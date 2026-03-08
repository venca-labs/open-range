"""Tests for OpenEnv-compatible model serialization."""

import json

from open_range.server.models import RangeAction, RangeObservation, RangeState


class TestRangeAction:
    """RangeAction serialization."""

    def test_create(self):
        a = RangeAction(command="nmap -sV web", mode="red")
        assert a.command == "nmap -sV web"
        assert a.mode == "red"

    def test_serialize_deserialize(self):
        a = RangeAction(command="curl http://web/", mode="red")
        data = a.model_dump()
        assert data["command"] == "curl http://web/"
        assert data["mode"] == "red"
        a2 = RangeAction(**data)
        assert a2.command == a.command
        assert a2.mode == a.mode

    def test_mode_literal(self):
        """mode must be 'red' or 'blue'."""
        a = RangeAction(command="x", mode="blue")
        assert a.mode == "blue"

    def test_json_roundtrip(self):
        a = RangeAction(command="hydra -l admin web ssh", mode="red")
        js = a.model_dump_json()
        a2 = RangeAction.model_validate_json(js)
        assert a2.command == a.command
        assert a2.mode == a.mode


class TestRangeObservation:
    """RangeObservation inherits done/reward from Observation base."""

    def test_defaults(self):
        obs = RangeObservation()
        assert obs.done is False
        assert obs.reward is None
        assert obs.stdout == ""
        assert obs.stderr == ""
        assert obs.flags_captured == []
        assert obs.alerts == []

    def test_done_inherited(self):
        obs = RangeObservation(done=True, reward=1.0)
        assert obs.done is True
        assert obs.reward == 1.0

    def test_custom_fields(self):
        obs = RangeObservation(
            stdout="flag found",
            flags_captured=["FLAG{test}"],
            alerts=["IDS alert"],
        )
        assert obs.flags_captured == ["FLAG{test}"]
        assert obs.alerts == ["IDS alert"]

    def test_json_roundtrip(self):
        obs = RangeObservation(
            stdout="output",
            stderr="err",
            done=True,
            reward=0.5,
            flags_captured=["FLAG{a}"],
            alerts=["alert1"],
        )
        js = obs.model_dump_json()
        obs2 = RangeObservation.model_validate_json(js)
        assert obs2.stdout == obs.stdout
        assert obs2.done is True
        assert obs2.reward == 0.5
        assert obs2.flags_captured == ["FLAG{a}"]


class TestRangeState:
    """RangeState inherits episode_id/step_count from State base."""

    def test_defaults(self):
        s = RangeState()
        assert s.episode_id is None
        assert s.step_count == 0
        assert s.mode == ""
        assert s.tier == 1
        assert s.flags_found == []

    def test_inherited_fields(self):
        s = RangeState(episode_id="ep_42", step_count=5)
        assert s.episode_id == "ep_42"
        assert s.step_count == 5

    def test_custom_fields(self):
        s = RangeState(
            episode_id="ep1",
            mode="red",
            tier=3,
            flags_found=["FLAG{a}"],
            services_status={"web": "running"},
        )
        assert s.tier == 3
        assert s.flags_found == ["FLAG{a}"]
        assert s.services_status["web"] == "running"

    def test_json_roundtrip(self):
        s = RangeState(
            episode_id="ep99",
            step_count=10,
            mode="blue",
            flags_found=["FLAG{x}"],
            tier=2,
        )
        js = s.model_dump_json()
        s2 = RangeState.model_validate_json(js)
        assert s2.episode_id == "ep99"
        assert s2.step_count == 10
        assert s2.mode == "blue"
        assert s2.tier == 2

    def test_model_dump_and_back(self):
        s = RangeState(episode_id="e1", step_count=3, mode="red", tier=1)
        d = s.model_dump()
        s2 = RangeState(**d)
        assert s2.episode_id == s.episode_id
        assert s2.step_count == s.step_count
