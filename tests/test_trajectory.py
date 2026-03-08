"""Tests for TrajectoryLogger -- JSONL export for SFT warm-start."""

import json
from pathlib import Path

import pytest

from open_range.training.trajectory import (
    Episode,
    TrajectoryLogger,
    Turn,
    RED_SYSTEM_PROMPT,
    BLUE_SYSTEM_PROMPT,
)


# ---------------------------------------------------------------------------
# Turn dataclass
# ---------------------------------------------------------------------------


class TestTurn:
    def test_basic_construction(self):
        t = Turn(role="red", observation="Range ready.", action="nmap -sV web", reward=0.1)
        assert t.role == "red"
        assert t.observation == "Range ready."
        assert t.action == "nmap -sV web"
        assert t.reward == 0.1
        assert t.timestamp > 0

    def test_timestamp_auto_set(self):
        t = Turn(role="blue", observation="ok", action="grep alert", reward=0.0)
        assert t.timestamp > 0


# ---------------------------------------------------------------------------
# Episode dataclass
# ---------------------------------------------------------------------------


class TestEpisode:
    def _make_episode(self) -> Episode:
        ep = Episode(episode_id="ep-1", snapshot_id="snap-1", tier=1)
        ep.turns = [
            Turn(role="red", observation="briefing", action="nmap -sV web", reward=0.1),
            Turn(role="blue", observation="alert: nmap", action="submit_finding nmap scan", reward=0.2),
            Turn(role="red", observation="ports found", action="curl http://web/search?q=test", reward=0.15),
            Turn(role="blue", observation="sql log", action="grep UNION /var/log/siem/web.log", reward=0.05),
            Turn(role="red", observation="sqli output", action="submit_flag FLAG{sqli_123}", reward=0.5),
        ]
        ep.outcome = "flag_captured"
        return ep

    def test_red_turns(self):
        ep = self._make_episode()
        assert len(ep.red_turns) == 3
        assert all(t.role == "red" for t in ep.red_turns)

    def test_blue_turns(self):
        ep = self._make_episode()
        assert len(ep.blue_turns) == 2
        assert all(t.role == "blue" for t in ep.blue_turns)

    def test_total_red_reward(self):
        ep = self._make_episode()
        expected = 0.1 + 0.15 + 0.5
        assert abs(ep.total_red_reward - expected) < 1e-6

    def test_total_blue_reward(self):
        ep = self._make_episode()
        expected = 0.2 + 0.05
        assert abs(ep.total_blue_reward - expected) < 1e-6

    def test_to_chat_messages_red(self):
        ep = self._make_episode()
        msgs = ep.to_chat_messages("red")
        # system + 3 * (user + assistant) = 7 messages
        assert len(msgs) == 7
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == RED_SYSTEM_PROMPT
        assert msgs[1]["role"] == "user"
        assert msgs[1]["content"] == "briefing"
        assert msgs[2]["role"] == "assistant"
        assert msgs[2]["content"] == "nmap -sV web"

    def test_to_chat_messages_blue(self):
        ep = self._make_episode()
        msgs = ep.to_chat_messages("blue")
        # system + 2 * (user + assistant) = 5 messages
        assert len(msgs) == 5
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == BLUE_SYSTEM_PROMPT

    def test_to_jsonl_record(self):
        ep = self._make_episode()
        record = ep.to_jsonl_record("red")
        assert record["episode_id"] == "ep-1"
        assert record["snapshot_id"] == "snap-1"
        assert record["tier"] == 1
        assert record["role"] == "red"
        assert record["outcome"] == "flag_captured"
        assert isinstance(record["messages"], list)
        assert isinstance(record["reward"], float)
        # Verify it's JSON-serializable
        json.dumps(record)


# ---------------------------------------------------------------------------
# TrajectoryLogger
# ---------------------------------------------------------------------------


class TestTrajectoryLogger:
    def test_start_episode(self):
        logger = TrajectoryLogger()
        ep = logger.start_episode("ep-1", snapshot_id="snap-1", tier=2)
        assert ep.episode_id == "ep-1"
        assert ep.snapshot_id == "snap-1"
        assert ep.tier == 2
        assert logger.current_episode is ep

    def test_log_turn(self):
        logger = TrajectoryLogger()
        logger.start_episode("ep-1")
        turn = logger.log_turn(role="red", observation="Ready.", action="nmap web", reward=0.1)
        assert turn.role == "red"
        assert len(logger.current_episode.turns) == 1

    def test_log_turn_without_episode_raises(self):
        logger = TrajectoryLogger()
        with pytest.raises(RuntimeError, match="No active episode"):
            logger.log_turn(role="red", observation="x", action="y")

    def test_end_episode(self):
        logger = TrajectoryLogger()
        logger.start_episode("ep-1")
        logger.log_turn(role="red", observation="Ready.", action="nmap web", reward=0.1)
        ep = logger.end_episode(outcome="timeout", metrics={"steps": 1})
        assert ep.outcome == "timeout"
        assert ep.metrics == {"steps": 1}
        assert logger.current_episode is None
        assert len(logger.episodes) == 1

    def test_end_episode_without_active_raises(self):
        logger = TrajectoryLogger()
        with pytest.raises(RuntimeError, match="No active episode"):
            logger.end_episode()

    def test_start_new_episode_abandons_current(self):
        logger = TrajectoryLogger()
        logger.start_episode("ep-1")
        logger.log_turn(role="red", observation="x", action="y")
        logger.start_episode("ep-2")
        assert len(logger.episodes) == 1
        assert logger.episodes[0].outcome == "abandoned"
        assert logger.current_episode.episode_id == "ep-2"

    def test_clear(self):
        logger = TrajectoryLogger()
        logger.start_episode("ep-1")
        logger.log_turn(role="red", observation="x", action="y")
        logger.end_episode()
        logger.clear()
        assert len(logger.episodes) == 0
        assert logger.current_episode is None


# ---------------------------------------------------------------------------
# JSONL export
# ---------------------------------------------------------------------------


class TestExportJsonl:
    def _build_logger_with_episodes(self) -> TrajectoryLogger:
        logger = TrajectoryLogger()

        # Episode 1: Red succeeds (high reward)
        logger.start_episode("ep-1", snapshot_id="snap-1", tier=1)
        logger.log_turn(role="red", observation="Range ready.", action="nmap -sV web", reward=0.1)
        logger.log_turn(role="blue", observation="Alert: nmap", action="submit_finding nmap", reward=0.2)
        logger.log_turn(role="red", observation="80/tcp open", action="curl http://web/search?q=1' OR 1=1--", reward=0.3)
        logger.log_turn(role="red", observation="FLAG{sqli}", action="submit_flag FLAG{sqli}", reward=0.5)
        logger.end_episode(outcome="flag_captured")

        # Episode 2: Both low reward (below typical threshold)
        logger.start_episode("ep-2", snapshot_id="snap-2", tier=1)
        logger.log_turn(role="red", observation="Range ready.", action="nmap -sV web", reward=0.01)
        logger.log_turn(role="blue", observation="No alerts", action="tail /var/log/siem/web.log", reward=0.01)
        logger.end_episode(outcome="timeout")

        return logger

    def test_export_creates_file(self, tmp_path: Path):
        logger = self._build_logger_with_episodes()
        out = tmp_path / "trajectories.jsonl"
        count = logger.export_jsonl(out)
        assert out.exists()
        assert count > 0

    def test_export_all_no_filter(self, tmp_path: Path):
        logger = self._build_logger_with_episodes()
        out = tmp_path / "all.jsonl"
        count = logger.export_jsonl(out, reward_threshold=0.0)
        # 2 episodes * 2 roles = 4 lines
        assert count == 4
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 4

    def test_export_with_reward_filter(self, tmp_path: Path):
        logger = self._build_logger_with_episodes()
        out = tmp_path / "filtered.jsonl"
        count = logger.export_jsonl(out, reward_threshold=0.1)
        # ep-1 red reward = 0.9, ep-1 blue reward = 0.2 -> both pass
        # ep-2 red reward = 0.01, ep-2 blue reward = 0.01 -> both filtered
        assert count == 2

    def test_export_single_role(self, tmp_path: Path):
        logger = self._build_logger_with_episodes()
        out = tmp_path / "red_only.jsonl"
        count = logger.export_jsonl(out, roles=("red",))
        # 2 episodes, red only = 2 lines
        assert count == 2

    def test_export_jsonl_format(self, tmp_path: Path):
        logger = self._build_logger_with_episodes()
        out = tmp_path / "format.jsonl"
        logger.export_jsonl(out)
        lines = out.read_text().strip().split("\n")
        for line in lines:
            record = json.loads(line)
            assert "episode_id" in record
            assert "snapshot_id" in record
            assert "tier" in record
            assert "role" in record
            assert "messages" in record
            assert "reward" in record
            assert "outcome" in record
            # Messages must follow chat format
            msgs = record["messages"]
            assert msgs[0]["role"] == "system"
            for msg in msgs:
                assert "role" in msg
                assert "content" in msg

    def test_export_creates_parent_dirs(self, tmp_path: Path):
        logger = self._build_logger_with_episodes()
        out = tmp_path / "nested" / "deep" / "trajectories.jsonl"
        count = logger.export_jsonl(out)
        assert out.exists()
        assert count > 0

    def test_export_empty_logger(self, tmp_path: Path):
        logger = TrajectoryLogger()
        out = tmp_path / "empty.jsonl"
        count = logger.export_jsonl(out)
        assert count == 0
        assert out.exists()
        assert out.read_text() == ""

    def test_red_and_blue_are_independent_examples(self, tmp_path: Path):
        """Red and Blue trajectories produce separate JSONL lines."""
        logger = self._build_logger_with_episodes()
        out = tmp_path / "independent.jsonl"
        logger.export_jsonl(out)
        lines = out.read_text().strip().split("\n")
        records = [json.loads(line) for line in lines]

        # Find ep-1 records
        ep1_records = [r for r in records if r["episode_id"] == "ep-1"]
        roles = {r["role"] for r in ep1_records}
        assert roles == {"red", "blue"}

        # Red and Blue have different system prompts
        for rec in ep1_records:
            system_msg = rec["messages"][0]
            if rec["role"] == "red":
                assert "penetration tester" in system_msg["content"]
            else:
                assert "SOC analyst" in system_msg["content"]
