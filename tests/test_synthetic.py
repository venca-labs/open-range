"""Tests for synthetic trajectory generation."""

from __future__ import annotations

import json
import os
import sys
import types

import pytest
from click.testing import CliRunner

from open_range.agents.llm_agent import LLMRangeAgent
from open_range.agents.replay_agent import ScriptedAgent, ScriptedBlueAgent, ScriptedRedAgent
from open_range.cli import cli
from open_range.server.models import RangeAction
from open_range.training.dataset import append_tool_context, load_jsonl_records, load_tool_context
from open_range.training.synthetic import (
    SyntheticRangeEnvironment,
    SyntheticTraceGenerator,
    build_teacher_agents,
    randomize_snapshot_flags,
)


class TestFlagRandomization:
    def test_randomize_snapshot_flags_rewrites_all_string_references(self, sample_snapshot_spec):
        snapshot = sample_snapshot_spec.model_copy(deep=True)
        original_flag = snapshot.flags[0].value
        snapshot.files["web:/tmp/flag.txt"] = f"echo {original_flag}"

        randomized = randomize_snapshot_flags(snapshot, seed=7)
        replaced_flag = randomized.flags[0].value

        assert replaced_flag != original_flag
        dumped = json.dumps(randomized.model_dump(mode="python"))
        assert original_flag not in dumped
        assert replaced_flag in dumped


class TestSyntheticEnvironment:
    def test_synthetic_environment_simulates_red_and_blue_flow(self, sample_snapshot_spec):
        env = SyntheticRangeEnvironment(randomize_flags=False, max_steps=5)

        try:
            reset_obs = env.reset(snapshot=sample_snapshot_spec, episode_id="synthetic-test")
            assert "RED BRIEFING" in reset_obs.stdout

            red_obs = env.step(
                RangeAction(
                    command="curl 'http://web/search?q=test%27+UNION+SELECT+flag+FROM+flags--'",
                    mode="red",
                )
            )
            assert "FLAG{test_sqli_123}" in red_obs.stdout

            blue_obs = env.step(
                RangeAction(
                    command="grep UNION /var/log/siem/consolidated/all.log",
                    mode="blue",
                )
            )
            assert "SQLi pattern detected" in blue_obs.stdout

            flag_obs = env.step(
                RangeAction(command="submit_flag FLAG{test_sqli_123}", mode="red")
            )
            assert flag_obs.done is True
            assert sample_snapshot_spec.flags[0].value in env.state.flags_found
        finally:
            env.close()


class TestSyntheticTraceGenerator:
    def test_export_jsonl_records_selected_roles(self, tmp_path, sample_snapshot_spec):
        red = ScriptedAgent(
            commands=[
                "nmap -sV 10.0.1.0/24",
                "submit_flag FLAG{test_sqli_123}",
            ]
        )
        blue = ScriptedAgent(commands=["grep scan /var/log/siem/consolidated/all.log"])
        generator = SyntheticTraceGenerator(
            snapshot=sample_snapshot_spec,
            red_agent=red,
            blue_agent=blue,
            max_steps=3,
            randomize_flags=False,
        )

        output_path = tmp_path / "synthetic.jsonl"
        logger, count = generator.export_jsonl(
            output_path,
            num_traces=1,
            roles=("red", "blue"),
        )

        assert count == 2
        assert len(logger.episodes) == 1
        assert logger.episodes[0].outcome == "flag_captured"

        records = [json.loads(line) for line in output_path.read_text().splitlines()]
        assert {record["role"] for record in records} == {"red", "blue"}
        assert all(record["messages"][0]["role"] == "system" for record in records)
        assert all(record["messages"][1]["role"] == "user" for record in records)
        assert any(message["role"] == "tool" for message in records[0]["messages"])
        assert all("metadata" in record for record in records)
        assert all("ground_truth_flag" in record for record in records)
        assert all("optimal_steps" in record for record in records)

    def test_build_teacher_agents_falls_back_to_scripted_when_no_model(self):
        red, blue = build_teacher_agents(teacher_model=None, roles=("red", "blue"))
        assert isinstance(red, ScriptedRedAgent)
        assert isinstance(blue, ScriptedBlueAgent)


class TestLiteLLMSupport:
    def test_codex_models_omit_temperature_and_enable_drop_params(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return types.SimpleNamespace(
                choices=[
                    types.SimpleNamespace(
                        message=types.SimpleNamespace(content="```bash\nwhoami\n```")
                    )
                ]
            )

        monkeypatch.setitem(sys.modules, "litellm", types.SimpleNamespace(completion=fake_completion))

        agent = LLMRangeAgent(model="azure/gpt-5.2-codex", temperature=0.6, max_tokens=64)
        agent.reset("Return exactly one command: whoami", "red")

        assert agent.act("Return exactly one command: whoami") == "whoami"
        assert captured["drop_params"] is True
        assert "temperature" not in captured

    def test_non_codex_models_keep_temperature(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_completion(**kwargs):
            captured.update(kwargs)
            return types.SimpleNamespace(
                choices=[
                    types.SimpleNamespace(
                        message=types.SimpleNamespace(content="echo ok")
                    )
                ]
            )

        monkeypatch.setitem(sys.modules, "litellm", types.SimpleNamespace(completion=fake_completion))

        agent = LLMRangeAgent(model="openai/gpt-4o", temperature=0.4, max_tokens=32)
        agent.reset("Return exactly one command: echo ok", "blue")

        assert agent.act("Return exactly one command: echo ok") == "echo ok"
        assert captured["temperature"] == 0.4
        assert captured["drop_params"] is True


class TestDatasetHelpers:
    def test_load_bootstrap_records_and_append_tool_context(self, tmp_path):
        bootstrap_path = tmp_path / "bootstrap.jsonl"
        bootstrap_path.write_text(
            json.dumps(
                {
                    "messages": [
                        {"role": "system", "content": "Seed system prompt"},
                        {"role": "user", "content": "obs"},
                        {"role": "assistant", "content": "cmd"},
                    ],
                    "metadata": {"source": "bootstrap"},
                }
            )
            + "\n"
        )
        tool_path = tmp_path / "tools.json"
        tool_path.write_text(
            json.dumps(
                [
                    {"name": "shell_command", "description": "Run a shell command"},
                    {"name": "read_file", "description": "Read file contents"},
                ]
            )
        )

        records = load_jsonl_records([bootstrap_path])
        tool_context = load_tool_context([tool_path])
        enriched = append_tool_context(records, tool_context)

        assert len(records) == 1
        assert "shell_command" in tool_context
        assert "Available tools" in enriched[0]["messages"][0]["content"]
        assert "read_file" in enriched[0]["messages"][0]["content"]


class TestSyntheticCLI:
    def test_cli_generates_jsonl_from_snapshot(self, tmp_path, sample_snapshot_spec):
        runner = CliRunner()
        snapshot_path = tmp_path / "spec.json"
        snapshot_path.write_text(json.dumps(sample_snapshot_spec.model_dump(mode="python")))
        output_path = tmp_path / "synthetic.jsonl"

        result = runner.invoke(
            cli,
            [
                "synthetic-data",
                "--snapshot",
                str(snapshot_path),
                "--output",
                str(output_path),
                "--num-traces",
                "1",
                "--max-steps",
                "3",
                "--roles",
                "red",
                "--reward-threshold",
                "-1",
                "--static-flags",
            ],
        )

        assert result.exit_code == 0, result.output
        assert output_path.exists()

        records = [json.loads(line) for line in output_path.read_text().splitlines()]
        assert len(records) == 1
        assert records[0]["role"] == "red"
        assert any(message["role"] == "tool" for message in records[0]["messages"])
        assert any(message.get("tool_calls") for message in records[0]["messages"] if message["role"] == "assistant")

    def test_cli_merges_bootstrap_traces_and_tool_info(self, tmp_path, sample_snapshot_spec):
        runner = CliRunner()
        snapshot_path = tmp_path / "spec.json"
        snapshot_path.write_text(json.dumps(sample_snapshot_spec.model_dump(mode="python")))
        bootstrap_path = tmp_path / "bootstrap.jsonl"
        bootstrap_path.write_text(
            json.dumps(
                {
                    "messages": [
                        {"role": "system", "content": "Bootstrap system"},
                        {"role": "user", "content": "bootstrap obs"},
                        {"role": "assistant", "content": "bootstrap cmd"},
                    ],
                    "metadata": {"source": "bootstrap"},
                }
            )
            + "\n"
        )
        tool_path = tmp_path / "tools.md"
        tool_path.write_text("- shell_command: Run shell commands\n- read_file: Read files\n")
        output_path = tmp_path / "merged.jsonl"

        result = runner.invoke(
            cli,
            [
                "synthetic-data",
                "--snapshot",
                str(snapshot_path),
                "--output",
                str(output_path),
                "--num-traces",
                "1",
                "--max-steps",
                "1",
                "--roles",
                "red",
                "--reward-threshold",
                "-1",
                "--bootstrap-traces",
                str(bootstrap_path),
                "--tool-info",
                str(tool_path),
                "--static-flags",
            ],
        )

        assert result.exit_code == 0, result.output
        records = [json.loads(line) for line in output_path.read_text().splitlines()]
        assert len(records) == 2
        assert records[0]["metadata"]["source"] == "bootstrap"
        assert "Available tools" in records[1]["messages"][0]["content"]
        assert "shell_command" in records[1]["messages"][0]["content"]

    def test_cli_can_emit_generated_only_while_using_bootstrap_examples(self, tmp_path, sample_snapshot_spec):
        runner = CliRunner()
        snapshot_path = tmp_path / "spec.json"
        snapshot_path.write_text(json.dumps(sample_snapshot_spec.model_dump(mode="python")))
        bootstrap_path = tmp_path / "bootstrap.jsonl"
        bootstrap_path.write_text(
            json.dumps(
                {
                    "messages": [
                        {"role": "system", "content": "Bootstrap system"},
                        {"role": "user", "content": "bootstrap prompt"},
                        {
                            "role": "assistant",
                            "content": "<think>Seed</think>",
                            "tool_calls": [
                                {
                                    "id": "call_seed",
                                    "type": "function",
                                    "function": {
                                        "name": "shell_command",
                                        "arguments": "{\"command\": \"whoami\"}",
                                    },
                                }
                            ],
                        },
                        {
                            "role": "tool",
                            "name": "shell_command",
                            "tool_call_id": "call_seed",
                            "content": "[0.2s] kali",
                        },
                    ],
                    "metadata": {"source": "bootstrap", "success": True, "total_turns": 4},
                }
            )
            + "\n"
        )
        output_path = tmp_path / "generated_only.jsonl"

        result = runner.invoke(
            cli,
            [
                "synthetic-data",
                "--snapshot",
                str(snapshot_path),
                "--output",
                str(output_path),
                "--num-traces",
                "1",
                "--max-steps",
                "1",
                "--roles",
                "red",
                "--reward-threshold",
                "-1",
                "--bootstrap-traces",
                str(bootstrap_path),
                "--bootstrap-examples",
                "1",
                "--generated-only",
                "--static-flags",
            ],
        )

        assert result.exit_code == 0, result.output
        records = [json.loads(line) for line in output_path.read_text().splitlines()]
        assert len(records) == 1
        assert records[0]["metadata"]["source"] == "open_range.synthetic"


@pytest.mark.live_model
def test_live_model_smoke_generates_a_synthetic_trace(tmp_path, sample_snapshot_spec):
    if not all(
        os.environ.get(name)
        for name in ("AZURE_API_KEY", "AZURE_API_BASE", "AZURE_API_VERSION")
    ):
        pytest.skip("Azure LiteLLM environment variables not configured")
    pytest.importorskip("litellm")

    snapshot = sample_snapshot_spec.model_copy(deep=True)
    snapshot.task.red_briefing = (
        "Synthetic smoke test. Return exactly one shell command. First command: whoami"
    )
    snapshot.task.blue_briefing = "Monitor the range."

    red, blue = build_teacher_agents(
        teacher_model=os.environ.get("OPENRANGE_SYNTH_MODEL", "azure/gpt-5.2-codex"),
        roles=("red",),
        temperature=None,
        max_tokens=96,
    )
    generator = SyntheticTraceGenerator(
        snapshot=snapshot,
        red_agent=red,
        blue_agent=blue,
        max_steps=1,
        randomize_flags=False,
    )

    output_path = tmp_path / "live_synthetic.jsonl"
    logger, count = generator.export_jsonl(
        output_path,
        num_traces=1,
        roles=("red",),
    )

    assert count == 1
    assert len(logger.episodes) == 1
    assert logger.episodes[0].red_turns
    assert logger.episodes[0].red_turns[0].action.strip()
    assert output_path.exists()
