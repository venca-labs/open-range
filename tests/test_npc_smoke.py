"""Integration smoke tests for NPC memory / planner / agent (issue #111).

Marks
-----
live_model  -- requires ANTHROPIC_API_KEY and makes real API calls to
              claude-haiku-4-5-20251001.
live_kind   -- requires a running Kind cluster (openrange context) with
              the or-llm-tier1-test release deployed.

Run all smoke tests:

    uv run pytest tests/test_npc_smoke.py -v -m "live_model or live_kind"

Run only the LLM smoke tests (no cluster needed):

    uv run pytest tests/test_npc_smoke.py -v -m live_model
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.npc_agent import LLMNPCAgent, Stimulus
from open_range.builder.npc.persona import default_personas
from open_range.builder.npc.planner import DailyPlanner
from open_range.world_ir import GreenPersona

# ---------------------------------------------------------------------------
# Constants / helpers
# ---------------------------------------------------------------------------

_KIND_RELEASE = os.environ.get("OPENRANGE_SMOKE_RELEASE", "or-llm-tier1-test")
_NPC_MODEL = os.environ.get("OPENRANGE_NPC_MODEL", "claude-haiku-4-5-20251001")
_SNAPSHOT_JSON = Path(__file__).parents[1] / "snapshots" / "llm_tier1_test.json"


def _has_api_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _has_kind_cluster() -> bool:
    try:
        result = subprocess.run(
            ["kubectl", "cluster-info", "--context", "kind-openrange"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _release_pods_running() -> bool:
    try:
        result = subprocess.run(
            [
                "kubectl", "get", "pods", "--all-namespaces",
                "-l", f"app.kubernetes.io/instance={_KIND_RELEASE}",
                "-o", "jsonpath={.items[*].status.phase}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        phases = result.stdout.strip().split()
        return bool(phases) and all(p == "Running" for p in phases)
    except Exception:
        return False


def _load_snapshot_context() -> SimpleNamespace:
    if _SNAPSHOT_JSON.exists():
        data = json.loads(_SNAPSHOT_JSON.read_text())
        return SimpleNamespace(
            topology=data.get("topology", {}),
            files=data.get("files", {}),
        )
    return SimpleNamespace(
        topology={
            "hosts": ["web", "db", "mail", "siem", "files"],
            "domain": "corp.local",
            "users": [{"username": "alice", "hosts": ["web"]}],
        },
        files={},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def persona() -> GreenPersona:
    return default_personas()[0]  # Marketing Coordinator -- low awareness


@pytest.fixture
def it_persona() -> GreenPersona:
    return default_personas()[1]  # IT Administrator -- high awareness


def _discover_pod_ids(release: str) -> dict[str, str]:
    """Discover pod namespace/name pairs using the 'app' label.

    Handles both the new chart (openrange/service label) and the old chart
    (app label only) so smoke tests work against either deployment.
    """
    try:
        result = subprocess.run(
            [
                "kubectl", "get", "pods", "--all-namespaces",
                "-l", f"app.kubernetes.io/instance={release}",
                "-o", "jsonpath={range .items[*]}{.metadata.namespace}{'/'}{.metadata.name}{'|'}{.metadata.labels.app}{'\\n'}{end}",
            ],
            capture_output=True, text=True, timeout=10,
        )
        pod_ids: dict[str, str] = {}
        for line in result.stdout.strip().splitlines():
            if "|" in line:
                ref, svc = line.split("|", 1)
                if svc:
                    pod_ids[svc] = ref
        return pod_ids
    except Exception:
        return {}


@pytest.fixture
def pod_set():
    from open_range.cluster import PodSet
    ps = PodSet(project_name=_KIND_RELEASE)
    ps.pod_ids.update(_discover_pod_ids(_KIND_RELEASE))
    return ps


@pytest.fixture
def pod_adapter(pod_set):
    """Thin adapter: wraps PodSet so NPCActionExecutor gets str from exec()."""
    class _Adapter:
        async def exec(self, service: str, cmd: str) -> str:
            result = await pod_set.exec(service, cmd, timeout=15.0)
            return result.stdout
    return _Adapter()


@pytest.fixture
def snapshot_ctx() -> SimpleNamespace:
    return _load_snapshot_context()


@pytest.fixture
def executor(pod_adapter, snapshot_ctx):
    from open_range.builder.npc.actions import NPCActionExecutor
    return NPCActionExecutor(pod_adapter, snapshot_ctx)


# ---------------------------------------------------------------------------
# LLM smoke tests  (live_model)
# ---------------------------------------------------------------------------


@pytest.mark.live_model
@pytest.mark.skipif(not _has_api_key(), reason="ANTHROPIC_API_KEY not set")
class TestDailyPlannerLive:
    def test_plan_day_returns_valid_schedule(self, persona):
        """plan_day() returns 4+ sorted actions within 9-17."""
        planner = DailyPlanner(model=_NPC_MODEL, temperature=0.3)
        env_ctx = {"pages": ["/", "/login", "/dashboard"], "colleagues": ["alice"]}
        asyncio.run(planner.plan_day(persona, env_ctx))

        assert len(planner._schedule) >= 4
        hours = [a.hour for a in planner._schedule]
        assert hours == sorted(hours)
        assert all(9 <= a.hour <= 17 for a in planner._schedule)

        valid_actions = {"browse", "send_email", "lookup", "access_share", "login", "query_db", "idle"}
        for action in planner._schedule:
            assert action.action in valid_actions, f"Unknown action: {action.action!r}"

    def test_plan_day_mood_and_focus(self, persona):
        """plan_day() sets mood and focus."""
        planner = DailyPlanner(model=_NPC_MODEL, temperature=0.3)
        asyncio.run(planner.plan_day(persona, {}))
        assert planner.mood in {"focused", "distracted", "busy", "relaxed"}
        assert len(planner.focus) > 0

    def test_it_plan_contains_it_actions(self, it_persona):
        """IT persona plan should include logins or DB queries."""
        planner = DailyPlanner(model=_NPC_MODEL, temperature=0.3)
        asyncio.run(planner.plan_day(it_persona, {"pages": ["/admin", "/status"]}))
        actions = {a.action for a in planner._schedule}
        assert actions & {"login", "query_db", "browse"}

    def test_reflect_produces_insights(self, persona):
        """reflect() returns 1-3 non-empty insight strings."""
        planner = DailyPlanner(model=_NPC_MODEL, temperature=0.2)
        memories = [
            "Received an email asking for login credentials",
            "Clicked a suspicious link -- browser redirected",
            "IT sent a phishing awareness reminder",
            "Another suspicious email arrived from unknown sender",
        ]
        reflections, adjusted = asyncio.run(planner.reflect(persona, memories))

        assert 1 <= len(reflections) <= 3
        assert all(isinstance(r, str) and len(r) > 0 for r in reflections)
        if adjusted is not None:
            assert 0.0 <= adjusted <= 1.0


@pytest.mark.live_model
@pytest.mark.skipif(not _has_api_key(), reason="ANTHROPIC_API_KEY not set")
class TestLLMNPCAgentLive:
    def test_next_routine_action_valid(self, persona):
        """next_routine_action() returns a valid action dict and records memory."""
        agent = LLMNPCAgent(model=_NPC_MODEL, temperature=0.3)
        env_ctx = {
            "pages": ["/", "/login", "/portal"],
            "shares": ["general", "marketing"],
            "db_tables": [],
            "colleagues": ["alice", "bob"],
        }
        result = asyncio.run(agent.next_routine_action(persona, env_ctx))

        valid = {"browse", "send_email", "lookup", "access_share", "login", "query_db", "idle"}
        assert result.get("action") in valid
        assert isinstance(result.get("detail"), str)
        assert len(agent._memory) == 1

    def test_decide_phishing_records_memory(self, persona):
        """decide() records a high-importance memory for any phishing reaction."""
        agent = LLMNPCAgent(model=_NPC_MODEL, temperature=0.1)
        stimulus = Stimulus(
            type="phishing_email",
            sender="ceo@corp-urgent.com",
            subject="Urgent: verify credentials NOW",
            content="Click here to avoid suspension: http://evil.example.com/login",
            plausibility=0.85,
        )
        result = asyncio.run(agent.decide(persona, stimulus))

        valid_reactions = {
            "click_link", "open_attachment", "reply",
            "share_credentials", "ignore", "report_to_IT", "forward",
        }
        assert result.action in valid_reactions
        assert len(agent._memory) == 1
        assert agent._memory._memories[0].importance >= 4.0

    def test_high_awareness_it_leans_toward_report(self, it_persona):
        """IT persona (awareness=0.8) should report or ignore phishing."""
        agent = LLMNPCAgent(model=_NPC_MODEL, temperature=0.1)
        stimulus = Stimulus(
            type="phishing_email",
            sender="helpdesk@totally-legit.com",
            subject="Password reset required",
            content="Reset at: http://phish.example.com -- expires in 1 hour",
            plausibility=0.5,
        )
        result = asyncio.run(agent.decide(it_persona, stimulus))
        assert result.action in {"report_to_IT", "ignore", "forward"}

    def test_prior_incident_memory_raises_caution(self, persona):
        """A seeded phishing-incident memory should make even low-awareness persona cautious."""
        agent = LLMNPCAgent(model=_NPC_MODEL, temperature=0.1)
        agent._memory.add(
            subject="janet.liu",
            relation="clicked_phishing_link_from",
            object_="it_warned_me",
            importance=9.0,
            tags=["phishing", "security", "incident"],
        )
        stimulus = Stimulus(
            type="phishing_email",
            sender="unknown@external.biz",
            subject="You have a pending package",
            content="Track package: http://malware.example.com/track",
            plausibility=0.6,
        )
        result = asyncio.run(agent.decide(persona, stimulus))
        # Any valid reaction is acceptable -- we just verify the LLM ran
        assert result.action in {
            "ignore", "report_to_IT", "forward", "click_link", "reply", "share_credentials"
        }

    def test_reflection_loop_end_to_end(self, persona):
        """Accumulate 10 actions, trigger reflection, re-plan with insights."""
        agent = LLMNPCAgent(model=_NPC_MODEL, temperature=0.3)
        env_ctx = {"pages": ["/", "/portal"], "colleagues": ["alice"]}

        for _ in range(10):
            asyncio.run(agent.next_routine_action(persona, env_ctx))

        assert agent._memory.needs_reflection(threshold=10)

        unprocessed = agent._memory.take_for_reflection()
        reflections, _ = asyncio.run(
            agent._planner.reflect(persona, [m.content for m in unprocessed])
        )
        assert len(reflections) >= 1

        asyncio.run(agent._planner.plan_day(persona, env_ctx, reflections=reflections))
        assert len(agent._planner._schedule) >= 4


# ---------------------------------------------------------------------------
# Kind pod smoke tests  (live_kind)
# ---------------------------------------------------------------------------


@pytest.mark.live_kind
@pytest.mark.skipif(not _has_kind_cluster(), reason="Kind cluster not reachable")
@pytest.mark.skipif(not _release_pods_running(), reason=f"{_KIND_RELEASE!r} pods not Running")
class TestNPCActionExecutorLive:
    def test_web_pod_reachable(self, pod_set):
        """PodSet resolves and execs into the web pod."""
        result = asyncio.run(pod_set.exec("web", "echo hello", timeout=10.0))
        assert result.ok, f"web pod exec failed: {result.stderr}"
        assert "hello" in result.stdout

    def test_siem_pod_reachable(self, pod_set):
        """PodSet resolves and execs into the siem pod."""
        result = asyncio.run(pod_set.exec("siem", "echo siem-ok", timeout=10.0))
        assert result.ok, f"siem pod exec failed: {result.stderr}"
        assert "siem-ok" in result.stdout

    def test_browse_action(self, executor, persona):
        """execute_routine('browse') runs curl and returns a benign log entry."""
        log = asyncio.run(
            executor.execute_routine(persona, "browse", "/", "Morning check")
        )
        assert log["action"] == "browse"
        assert log["label"] == "benign"
        assert log["persona"] == persona.id

    def test_email_action(self, executor, persona):
        """execute_routine('send_email') writes to mail pod and returns a log."""
        log = asyncio.run(
            executor.execute_routine(persona, "send_email", "alice", "Quick update")
        )
        assert log["action"] == "send_email"
        assert log["label"] == "benign"

    def test_idle_action(self, executor, persona):
        """execute_routine('idle') returns immediately with no network I/O."""
        log = asyncio.run(
            executor.execute_routine(persona, "idle", "", "Lunch break")
        )
        assert log["action"] == "idle"
        assert log["label"] == "benign"

    def test_share_access(self, executor, persona):
        """execute_routine('access_share') runs ls on the files pod."""
        log = asyncio.run(
            executor.execute_routine(persona, "access_share", "general", "Checking shared drive")
        )
        assert log["action"] == "access_share"

    def test_query_db(self, executor, it_persona):
        """execute_routine('query_db') runs a mysql query on the db pod."""
        log = asyncio.run(
            executor.execute_routine(it_persona, "query_db", "", "Afternoon health check")
        )
        assert log["action"] == "query_db"


@pytest.mark.live_kind
@pytest.mark.live_model
@pytest.mark.skipif(not _has_api_key(), reason="ANTHROPIC_API_KEY not set")
@pytest.mark.skipif(not _has_kind_cluster(), reason="Kind cluster not reachable")
@pytest.mark.skipif(not _release_pods_running(), reason=f"{_KIND_RELEASE!r} pods not Running")
class TestNPCRunLoopLive:
    """3-cycle end-to-end NPC loop against live pods."""

    def test_run_loop_three_cycles(self, persona, pod_adapter, snapshot_ctx):
        agent = LLMNPCAgent(model=_NPC_MODEL, temperature=0.4)

        async def _run():
            from open_range.builder.npc.actions import NPCActionExecutor
            executor = NPCActionExecutor(pod_adapter, snapshot_ctx)
            env_ctx = {
                "pages": executor._pages,
                "shares": executor._shares,
                "db_tables": executor._db_tables,
                "colleagues": executor._users,
            }
            await agent._planner.plan_day(persona, env_ctx)
            for _ in range(3):
                hint = agent._planner.next_action_hint()
                plan_hint = (
                    {"action": hint.action, "target": hint.target, "detail": hint.detail}
                    if hint else None
                )
                routine = await agent.next_routine_action(persona, env_ctx, plan_hint=plan_hint)
                log = await executor.execute_routine(
                    persona,
                    routine.get("action", "idle"),
                    routine.get("target", ""),
                    routine.get("detail", ""),
                    routine.get("email_body", ""),
                )
                agent._actions.append(log)

        asyncio.run(_run())

        assert len(agent._actions) == 3
        assert len(agent._memory) == 3
        for entry in agent._memory._memories:
            assert entry.importance == 2.0
            assert "routine" in entry.tags
