"""Tests for the NPC agent system."""

from __future__ import annotations

import pytest

from open_range.agents import (
    Memory,
    NPCAgent,
    _event_susceptibility_key,
    _routine_dispatch,
    build_agents,
    generate_personas,
)
from open_range.runtime_types import RuntimeEvent
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _persona(
    pid: str = "alice",
    awareness: float = 0.5,
    department: str = "Engineering",
    routine: tuple[str, ...] = ("browse_app", "check_mail"),
) -> GreenPersona:
    return GreenPersona(
        id=pid,
        role="Engineer",
        department=department,
        home_host="host-web",
        mailbox=f"{pid}@company.local",
        awareness=awareness,
        susceptibility={"phishing": 0.6, "credential_theft": 0.4},
        routine=routine,
    )


def _event(
    event_type: str = "InitialAccess",
    malicious: bool = True,
    suspicious: bool = True,
    time: float = 1.0,
) -> RuntimeEvent:
    return RuntimeEvent(
        id=f"evt-test-{time}",
        time=time,
        event_type=event_type,
        source_entity="svc-web",
        target_entity="svc-web",
        actor="red",
        malicious=malicious,
        suspicious=suspicious,
    )


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------


class TestMemory:
    def test_add_and_retrieve(self) -> None:
        mem = Memory(capacity=10)
        mem.add(_event())
        assert len(mem.top(k=5, current_time=1.0)) == 1

    def test_capacity_enforced(self) -> None:
        mem = Memory(capacity=3)
        for t in range(5):
            mem.add(_event(time=float(t)))
        assert len(mem.top(k=10, current_time=5.0)) == 3

    def test_recency_preference(self) -> None:
        mem = Memory(capacity=10)
        mem.add(
            _event(
                time=1.0,
                event_type="BenignUserAction",
                malicious=False,
                suspicious=False,
            )
        )
        mem.add(_event(time=10.0, event_type="InitialAccess"))
        top = mem.top(k=1, current_time=10.0)
        assert top[0].event_type == "InitialAccess"

    def test_importance_preference(self) -> None:
        mem = Memory(capacity=10)
        mem.add(_event(time=5.0, malicious=False, suspicious=False))
        mem.add(_event(time=5.0, malicious=True, suspicious=True))
        top = mem.top(k=1, current_time=5.0)
        assert top[0].malicious is True

    def test_suspicious_count(self) -> None:
        mem = Memory(capacity=10)
        mem.add(_event(suspicious=True))
        mem.add(_event(suspicious=False, malicious=False))
        mem.add(_event(suspicious=True))
        assert mem.suspicious_count() == 2

    def test_reset(self) -> None:
        mem = Memory()
        mem.add(_event())
        mem.reset()
        assert len(mem.top(k=5)) == 0

    def test_to_dicts(self) -> None:
        mem = Memory()
        mem.add(_event())
        dicts = mem.to_dicts()
        assert len(dicts) == 1
        assert "time" in dicts[0]


# ---------------------------------------------------------------------------
# NPCAgent
# ---------------------------------------------------------------------------


class TestNPCAgent:
    def test_observe_updates_awareness(self) -> None:
        agent = NPCAgent(persona=_persona(awareness=0.3))
        agent.observe(_event(suspicious=True))
        assert agent.effective_awareness == pytest.approx(0.4)

    def test_awareness_caps_at_one(self) -> None:
        agent = NPCAgent(persona=_persona(awareness=0.9))
        for _ in range(10):
            agent.observe(_event(suspicious=True))
        assert agent.effective_awareness == 1.0

    def test_routine_action(self) -> None:
        agent = NPCAgent(persona=_persona(routine=("check_mail", "browse_app")))
        a0 = agent.routine_action(slot=0)
        assert a0.kind == "mail"
        a1 = agent.routine_action(slot=1)
        assert a1.kind == "api"

    def test_gossip_with_trusted(self) -> None:
        agent = NPCAgent(
            persona=_persona(),
            relationships={"bob": 0.8, "carol": 0.3},
        )
        action = agent.gossip_action(_event())
        assert action is not None
        assert action.kind == "chat"
        assert action.payload["to"] == "bob"

    def test_gossip_no_trusted(self) -> None:
        agent = NPCAgent(
            persona=_persona(),
            relationships={"carol": 0.2},
        )
        assert agent.gossip_action(_event()) is None

    def test_gossip_no_relationships(self) -> None:
        agent = NPCAgent(persona=_persona())
        assert agent.gossip_action(_event()) is None

    def test_reset(self) -> None:
        agent = NPCAgent(persona=_persona(awareness=0.3))
        agent.observe(_event())
        agent.reset()
        assert agent.effective_awareness == 0.3
        assert len(agent.memory.top(k=5)) == 0


# ---------------------------------------------------------------------------
# PersonaFactory
# ---------------------------------------------------------------------------


class TestPersonaFactory:
    def test_generate_10_personas(self) -> None:
        personas = generate_personas(count=10, seed=42)
        assert len(personas) == 10

    def test_generate_20_personas(self) -> None:
        personas = generate_personas(count=20, seed=99)
        assert len(personas) == 20

    def test_unique_ids(self) -> None:
        personas = generate_personas(count=15, seed=42)
        ids = [p.id for p in personas]
        assert len(ids) == len(set(ids))

    def test_diverse_departments(self) -> None:
        personas = generate_personas(count=14, seed=42)
        departments = {p.department for p in personas}
        assert len(departments) >= 4

    def test_awareness_in_range(self) -> None:
        personas = generate_personas(count=10, seed=42)
        for p in personas:
            assert 0.0 <= p.awareness <= 1.0

    def test_all_have_routines(self) -> None:
        personas = generate_personas(count=10, seed=42)
        for p in personas:
            assert len(p.routine) >= 2

    def test_all_have_susceptibility(self) -> None:
        personas = generate_personas(count=10, seed=42)
        for p in personas:
            assert len(p.susceptibility) >= 1

    def test_deterministic(self) -> None:
        p1 = generate_personas(count=10, seed=42)
        p2 = generate_personas(count=10, seed=42)
        assert [p.id for p in p1] == [p.id for p in p2]


# ---------------------------------------------------------------------------
# build_agents
# ---------------------------------------------------------------------------


class TestBuildAgents:
    def test_builds_all(self) -> None:
        personas = generate_personas(count=10, seed=42)
        agents = build_agents(personas)
        assert len(agents) == 10

    def test_relationships_auto_derived(self) -> None:
        personas = generate_personas(count=10, seed=42)
        agents = build_agents(personas)
        for agent in agents.values():
            # Each agent has relationships to all others
            assert len(agent.relationships) == 9

    def test_same_department_higher_trust(self) -> None:
        alice = _persona("alice", department="Engineering")
        bob = _persona("bob", department="Engineering")
        carol = _persona("carol", department="Sales")
        agents = build_agents((alice, bob, carol))
        # Alice trusts bob (same dept) more than carol
        assert (
            agents["alice"].relationships["bob"]
            > agents["alice"].relationships["carol"]
        )


# ---------------------------------------------------------------------------
# Dispatch helpers
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_exact(self) -> None:
        assert _routine_dispatch("check_mail") == ("mail", "svc-email")
        assert _routine_dispatch("browse_app") == ("api", "svc-web")
        assert _routine_dispatch("chat_colleague") == ("chat", "svc-web")
        assert _routine_dispatch("share_document") == (
            "document_share",
            "svc-fileshare",
        )

    def test_fallback(self) -> None:
        assert _routine_dispatch("custom_mail_task")[0] == "mail"
        assert _routine_dispatch("unknown_thing") == ("api", "svc-web")

    def test_susceptibility_key(self) -> None:
        assert _event_susceptibility_key("InitialAccess") == "initial_access"
        assert _event_susceptibility_key("CredentialObtained") == "credential_obtained"
