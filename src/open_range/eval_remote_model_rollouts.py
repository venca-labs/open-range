"""Run an action-first remote model rollout eval against admitted snapshots."""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

import httpx
from pydantic import ValidationError

from open_range._decision_sft import build_decision_prompt, system_prompt_for_role
from open_range._reference_replay import action_for_reference_step
from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.build_config import BuildConfig
from open_range.curriculum import FrontierMutationPolicy, PopulationStats
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.resources import load_bundled_manifest
from open_range.runtime import OpenRangeRuntime
from open_range.runtime_types import Action
from open_range.snapshot import RuntimeSnapshot
from open_range.store import FileSnapshotStore
from open_range.training_data import (
    TraceLineage,
    public_trace_action,
    render_action_text,
)

DEFAULT_ENDPOINT = os.environ.get(
    "OPENAI_CHAT_COMPLETIONS_URL", "http://localhost:8001/v1/chat/completions"
)
DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gemma-4-31b-sft")
VALIDATION_PROFILES = ("full", "no_necessity", "graph_plus_live", "graph_only")
ValidationProfile = Literal["full", "no_necessity", "graph_plus_live", "graph_only"]
_ACTION_EXAMPLE = (
    '{"actor_id":"red","role":"red","kind":"sleep","payload":{},"timeout_s":30.0}'
)


def _default_manifest_name() -> str:
    return "tier1_basic.yaml"


def _build_config_for_eval(validation_profile: ValidationProfile) -> BuildConfig:
    return BuildConfig(validation_profile=validation_profile)


def _load_manifest(source: str | Path | None) -> dict[str, Any]:
    if source is None:
        return load_bundled_manifest(_default_manifest_name())
    path = Path(source)
    if path.exists():
        import yaml

        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"expected a YAML mapping in {path}")
        return payload
    return load_bundled_manifest(str(source))


def reference_match_rate(picks: list[dict[str, Any]]) -> float:
    if not picks:
        return 0.0
    return sum(1 for pick in picks if pick.get("reference_match")) / len(picks)


def valid_action_rate(picks: list[dict[str, Any]]) -> float:
    if not picks:
        return 0.0
    return sum(1 for pick in picks if pick.get("valid_response")) / len(picks)


def avg_latency_ms(picks: list[dict[str, Any]]) -> float:
    if not picks:
        return 0.0
    return sum(float(pick.get("latency_ms", 0.0)) for pick in picks) / len(picks)


def build_messages(
    snapshot: RuntimeSnapshot, observation, decision_index: int
) -> list[dict[str, str]]:
    user_prompt = build_decision_prompt(
        snapshot_id=snapshot.snapshot_id,
        world_id=snapshot.world.world_id,
        world_hash=snapshot.world_hash,
        lineage=TraceLineage(
            root_world_id=snapshot.parent_world_id or snapshot.world.world_id,
            generation=snapshot.world.lineage.generation,
            parent_world_id=snapshot.parent_world_id,
            mutation_ops=tuple(snapshot.world.lineage.mutation_ops),
        ),
        mode="red_only",
        start_state="clean",
        role="red",
        decision_index=decision_index,
        observation=observation,
        weaknesses=(),
        benchmark_tags=(),
        trace_source="runtime",
        action_source="reference_runtime",
        split="test",
        prompt_mode="zero_day",
    )
    return [
        {"role": "system", "content": system_prompt_for_role("red")},
        {
            "role": "user",
            "content": (
                user_prompt
                + "\nReturn JSON only."
                + "\nAllowed action kinds: shell, api, mail, control, submit_finding, sleep."
                + f"\nExample: {_ACTION_EXAMPLE}"
            ),
        },
    ]


def _message_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return ""


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if not lines:
        return stripped
    if lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_json_candidates(text: str) -> list[str]:
    stripped = _strip_code_fence(text)
    candidates: list[str] = [stripped]
    if "<action_json>" in stripped and "</action_json>" in stripped:
        start = stripped.index("<action_json>") + len("<action_json>")
        end = stripped.index("</action_json>", start)
        candidates.append(stripped[start:end].strip())
    first = stripped.find("{")
    last = stripped.rfind("}")
    if first != -1 and last != -1 and first < last:
        candidates.append(stripped[first : last + 1].strip())
    seen: set[str] = set()
    return [
        candidate
        for candidate in candidates
        if candidate and not (candidate in seen or seen.add(candidate))
    ]


def _coerce_action_payload(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("action")
    if isinstance(nested, dict):
        payload = dict(nested)
    nested_json = payload.get("action_json")
    if isinstance(nested_json, dict):
        payload = dict(nested_json)

    candidate = dict(payload)
    candidate["actor_id"] = "red"
    candidate["role"] = "red"
    payload_dict = candidate.get("payload")
    if not isinstance(payload_dict, dict):
        payload_dict = {}
    for key in (
        "target",
        "command",
        "path",
        "query",
        "event_type",
        "event",
        "action",
        "subject",
        "to",
    ):
        if key in candidate and key not in payload_dict:
            payload_dict[key] = candidate.pop(key)
    candidate["payload"] = payload_dict
    candidate.setdefault("timeout_s", 30.0)
    return candidate


def parse_action_response(text: str) -> tuple[Action | None, str]:
    if not text.strip():
        return None, "empty response"

    last_error = "could not parse action json"
    for candidate_text in _extract_json_candidates(text):
        try:
            payload = json.loads(candidate_text)
        except json.JSONDecodeError as exc:
            last_error = f"invalid json: {exc.msg}"
            continue
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                last_error = f"invalid nested json: {exc.msg}"
                continue
        if not isinstance(payload, dict):
            last_error = f"expected JSON object, got {type(payload).__name__}"
            continue
        try:
            action = Action.model_validate(_coerce_action_payload(payload))
        except ValidationError as exc:
            last_error = str(exc)
            continue
        return action, ""
    return None, last_error


def _fallback_action() -> Action:
    return Action(actor_id="red", role="red", kind="sleep", payload={})


@dataclass(frozen=True)
class RemoteChoice:
    action: Action
    raw_text: str
    valid: bool
    latency_ms: float
    finish_reason: str
    usage: dict[str, Any]
    parse_error: str = ""


class RemoteChatClient:
    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        api_key: str = "",
        timeout_s: float = 60.0,
        temperature: float = 0.0,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self._client = httpx.Client(timeout=timeout_s)

    def __enter__(self) -> RemoteChatClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        del exc_type, exc, tb
        self.close()

    def close(self) -> None:
        self._client.close()

    def choose(self, *, messages: list[dict[str, str]]) -> RemoteChoice:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": 160,
        }
        started = time.perf_counter()
        response = self._client.post(self.endpoint, json=payload, headers=headers)
        response.raise_for_status()
        latency_ms = (time.perf_counter() - started) * 1000.0
        body = response.json()
        choice = body["choices"][0]
        raw_text = _message_content_text(choice.get("message", {}).get("content", ""))
        action, parse_error = parse_action_response(raw_text)
        if action is None:
            action = _fallback_action()
        return RemoteChoice(
            action=action,
            raw_text=raw_text,
            valid=not parse_error,
            latency_ms=latency_ms,
            finish_reason=str(choice.get("finish_reason", "")),
            usage=body.get("usage", {}) if isinstance(body.get("usage"), dict) else {},
            parse_error=parse_error,
        )


def evaluate_remote_model_rollouts(
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    model: str = DEFAULT_MODEL,
    api_key: str = "",
    validation_profile: ValidationProfile = "full",
    manifest: str | Path | None = None,
    mutations: int = 3,
    max_turns: int = 8,
    timeout_s: float = 60.0,
    quiet: bool = False,
) -> dict[str, Any]:
    payload = _load_manifest(manifest)
    mutation_policy = FrontierMutationPolicy()
    build_config = _build_config_for_eval(validation_profile)
    with TemporaryDirectory(prefix="openrange-remote-model-rollout-") as tmp:
        root = Path(tmp)
        store = FileSnapshotStore(root / "snapshots")
        pipeline = BuildPipeline(store=store)

        snapshots: list[RuntimeSnapshot] = []
        current = hydrate_runtime_snapshot(
            store,
            pipeline.admit(
                pipeline.build(payload, root / "rendered-base", build_config),
                split="train",
            ),
        )
        snapshots.append(current)
        for idx in range(1, mutations + 1):
            parent_stats = PopulationStats(
                snapshot_id=current.snapshot_id,
                world_id=current.world.world_id,
                split="train",
                episodes=4,
                red_win_rate=0.25 if idx % 2 else 0.65,
                blue_win_rate=0.75 if idx % 2 else 0.35,
                avg_ticks=6.0 + idx,
                flake_rate=0.0,
                novelty=min(0.5 + idx * 0.1, 1.0),
                blue_signal_points=current.validator_report.blue_signal_points,
            )
            child_world = mutation_policy.mutate(
                current.world, parent_stats=parent_stats
            )
            current = hydrate_runtime_snapshot(
                store,
                pipeline.admit_child(
                    child_world,
                    root / f"rendered-child-{idx}",
                    split="eval",
                    build_config=build_config,
                ),
            )
            snapshots.append(current)

        reports: list[dict[str, Any]] = []
        reference_matches = 0
        valid_actions = 0
        total_picks = 0
        red_wins = 0
        total_pairs = 0
        latency_total_ms = 0.0

        with RemoteChatClient(
            endpoint=endpoint,
            model=model,
            api_key=api_key,
            timeout_s=timeout_s,
        ) as client:
            for snapshot in snapshots:
                pair_reports: list[dict[str, Any]] = []
                for attack_trace_index in range(
                    max(1, len(snapshot.reference_bundle.reference_attack_traces))
                ):
                    total_pairs += 1
                    runtime = OpenRangeRuntime()
                    runtime.reset(
                        snapshot,
                        EpisodeConfig(
                            mode="red_only",
                            scheduler_mode="strict_turns",
                            opponent_blue="scripted",
                        ),
                        reference_attack_index=attack_trace_index,
                    )
                    picks: list[dict[str, Any]] = []
                    turns = 0
                    while not runtime.state().done and turns < max_turns:
                        try:
                            decision = runtime.next_decision()
                        except RuntimeError:
                            if runtime.state().done:
                                break
                            raise
                        expected_step = runtime.reference_step("red")
                        reference_action = action_for_reference_step(
                            snapshot, "red", expected_step
                        )
                        choice = client.choose(
                            messages=build_messages(snapshot, decision.obs, turns)
                        )
                        result = runtime.act("red", choice.action)
                        reference_match = (
                            runtime.matches_reference_step(
                                choice.action, expected_step, result.stdout
                            )
                            if expected_step is not None
                            else public_trace_action(choice.action).model_dump(
                                mode="json"
                            )
                            == public_trace_action(reference_action).model_dump(
                                mode="json"
                            )
                        )
                        turns += 1
                        total_picks += 1
                        latency_total_ms += choice.latency_ms
                        if reference_match:
                            reference_matches += 1
                        if choice.valid:
                            valid_actions += 1
                        picks.append(
                            {
                                "chosen_action": public_trace_action(
                                    choice.action
                                ).model_dump(mode="json"),
                                "chosen_action_text": render_action_text(choice.action),
                                "reference_action": public_trace_action(
                                    reference_action
                                ).model_dump(mode="json"),
                                "reference_action_text": render_action_text(
                                    reference_action
                                ),
                                "reference_match": reference_match,
                                "valid_response": choice.valid,
                                "raw_response": choice.raw_text,
                                "parse_error": choice.parse_error,
                                "finish_reason": choice.finish_reason,
                                "latency_ms": choice.latency_ms,
                                "usage": choice.usage,
                                "result_stdout": result.stdout,
                                "result_stderr": result.stderr,
                            }
                        )

                    score = runtime.score()
                    if score.winner == "red":
                        red_wins += 1
                    truncated = not runtime.state().done
                    pair_reports.append(
                        {
                            "attack_trace_index": attack_trace_index,
                            "done": score.done,
                            "truncated": truncated,
                            "winner": score.winner,
                            "terminal_reason": score.terminal_reason
                            or ("max_turns_reached" if truncated else ""),
                            "red_reward": score.red_reward,
                            "blue_reward": score.blue_reward,
                            "turns": turns,
                            "reference_match_rate": reference_match_rate(picks),
                            "exact_pick_rate": reference_match_rate(picks),
                            "valid_action_rate": valid_action_rate(picks),
                            "valid_response_rate": valid_action_rate(picks),
                            "avg_latency_ms": avg_latency_ms(picks),
                            "picks": picks,
                        }
                    )
                reports.append(
                    {
                        "snapshot_id": snapshot.snapshot_id,
                        "world_id": snapshot.world.world_id,
                        "red_win_rate": sum(
                            1 for report in pair_reports if report["winner"] == "red"
                        )
                        / len(pair_reports)
                        if pair_reports
                        else 0.0,
                        "reference_match_rate": sum(
                            report["reference_match_rate"] for report in pair_reports
                        )
                        / len(pair_reports)
                        if pair_reports
                        else 0.0,
                        "exact_pick_rate": sum(
                            report["exact_pick_rate"] for report in pair_reports
                        )
                        / len(pair_reports)
                        if pair_reports
                        else 0.0,
                        "valid_action_rate": sum(
                            report["valid_action_rate"] for report in pair_reports
                        )
                        / len(pair_reports)
                        if pair_reports
                        else 0.0,
                        "valid_response_rate": sum(
                            report["valid_response_rate"] for report in pair_reports
                        )
                        / len(pair_reports)
                        if pair_reports
                        else 0.0,
                        "avg_latency_ms": sum(
                            report["avg_latency_ms"] for report in pair_reports
                        )
                        / len(pair_reports)
                        if pair_reports
                        else 0.0,
                        "pairs": pair_reports,
                        "weakness_count": len(snapshot.world.weaknesses),
                    }
                )

        result = {
            "manifest_source": str(manifest)
            if manifest is not None
            else _default_manifest_name(),
            "endpoint": endpoint,
            "model": model,
            "validation_profile": validation_profile,
            "snapshot_count": len(reports),
            "red_win_rate": red_wins / total_pairs if total_pairs else 0.0,
            "reference_match_rate": (
                reference_matches / total_picks if total_picks else 0.0
            ),
            "exact_pick_rate": reference_matches / total_picks if total_picks else 0.0,
            "valid_action_rate": valid_actions / total_picks if total_picks else 0.0,
            "valid_response_rate": valid_actions / total_picks if total_picks else 0.0,
            "avg_latency_ms": latency_total_ms / total_picks if total_picks else 0.0,
            "reports": reports,
        }
        if not quiet:
            print(f"manifest={result['manifest_source']}")
            print(f"endpoint={result['endpoint']}")
            print(f"model={result['model']}")
            print(f"validation_profile={result['validation_profile']}")
            print(f"snapshots={result['snapshot_count']}")
            print(f"red_win_rate={result['red_win_rate']:.3f}")
            print(f"reference_match_rate={result['reference_match_rate']:.3f}")
            print(f"valid_action_rate={result['valid_action_rate']:.3f}")
            print(f"avg_latency_ms={result['avg_latency_ms']:.1f}")
        return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an action-first remote-model OpenRange rollout eval."
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help="OpenAI-compatible /v1/chat/completions endpoint URL.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Model id sent to the OpenAI-compatible endpoint.",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("OPENAI_API_KEY", ""),
        help="Optional API key for the remote chat endpoint.",
    )
    parser.add_argument(
        "--validation-profile",
        default="full",
        choices=VALIDATION_PROFILES,
        help=(
            "Admission strictness for the eval snapshots. "
            "Use graph_only only for explicit offline evaluation."
        ),
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Bundled manifest name or path to strict manifest YAML.",
    )
    parser.add_argument("--mutations", type=int, default=3)
    parser.add_argument("--max-turns", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--out", default="/tmp/openrange-remote-model-rollout.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = evaluate_remote_model_rollouts(
        endpoint=args.endpoint,
        model=args.model,
        api_key=args.api_key,
        validation_profile=args.validation_profile,
        manifest=args.manifest,
        mutations=args.mutations,
        max_turns=args.max_turns,
        timeout_s=args.timeout,
        quiet=False,
    )
    out_path = Path(args.out)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"report={out_path}")
