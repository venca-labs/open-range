"""Behavioral tests for cyber NPCs.

The NPCs receive an ``interface`` dict matching the HTTP backing's
shape (``{base_url, http_get, http_get_json}``). Tests use a fake
interface that records GET calls so we can assert on cadence,
rotation, and graceful error handling.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyber_webapp.npcs.admin_audit import (
    AdminAudit,
)
from cyber_webapp.npcs.admin_audit import (
    factory as admin_audit_factory,
)
from cyber_webapp.npcs.browsing_user import (
    BrowsingUser,
)
from cyber_webapp.npcs.browsing_user import (
    factory as browsing_user_factory,
)


class _FakeInterface(dict[str, Any]):
    """Mimics ``HTTPBacking.interface``: a dict with an ``http_get`` callable."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

        def http_get(path: object) -> bytes:
            self.calls.append(str(path))
            return b""

        self["base_url"] = "http://test.local"
        self["http_get"] = http_get


# ---------------------------------------------------------------------------
# BrowsingUser
# ---------------------------------------------------------------------------


def test_browsing_user_acts_on_first_step_then_obeys_cadence() -> None:
    npc = BrowsingUser(cadence_ticks=3, paths=("/a",))
    iface = _FakeInterface()

    # First tick: act.
    npc.step(iface)
    assert iface.calls == ["/a"]

    # Next two ticks: silent (cooldown).
    npc.step(iface)
    npc.step(iface)
    assert iface.calls == ["/a"]

    # Cooldown elapsed: act again.
    npc.step(iface)
    assert iface.calls == ["/a", "/a"]


def test_browsing_user_rotates_through_paths() -> None:
    npc = BrowsingUser(cadence_ticks=1, paths=("/a", "/b", "/c"))
    iface = _FakeInterface()
    for _ in range(7):
        npc.step(iface)
    # cadence_ticks=1: every step acts → 7 calls cycling a→b→c→a→b→c→a
    assert iface.calls == ["/a", "/b", "/c", "/a", "/b", "/c", "/a"]


def test_browsing_user_swallows_http_errors() -> None:
    npc = BrowsingUser(cadence_ticks=1, paths=("/boom",))

    def boom(path: object) -> bytes:
        raise RuntimeError("HTTP exploded")

    iface: dict[str, Any] = {"base_url": "http://x", "http_get": boom}
    # Should not raise — NPC failures must not sink the episode.
    npc.step(iface)
    npc.step(iface)


def test_browsing_user_no_op_when_interface_missing_http_get() -> None:
    npc = BrowsingUser(cadence_ticks=1, paths=("/a",))
    npc.step({})  # missing http_get → silent no-op


def test_browsing_user_rejects_invalid_construction() -> None:
    with pytest.raises(ValueError, match="cadence_ticks"):
        BrowsingUser(cadence_ticks=0)
    with pytest.raises(ValueError, match="paths"):
        BrowsingUser(paths=())


def test_browsing_user_factory_reads_config() -> None:
    npc = browsing_user_factory(
        {
            "cadence_ticks": 4,
            "paths": ["/x", "/y"],
            "timeout_seconds": 0.5,
        },
    )
    assert isinstance(npc, BrowsingUser)
    iface = _FakeInterface()
    # First tick acts; next 3 silent; 5th acts again.
    for _ in range(5):
        npc.step(iface)
    assert iface.calls == ["/x", "/y"]


def test_browsing_user_factory_rejects_bad_config() -> None:
    with pytest.raises(ValueError, match="paths must be a list"):
        browsing_user_factory({"paths": "not-a-list"})
    with pytest.raises(ValueError, match="cadence_ticks must be an int"):
        browsing_user_factory({"cadence_ticks": "fast"})


# ---------------------------------------------------------------------------
# AdminAudit
# ---------------------------------------------------------------------------


def test_admin_audit_polls_audit_path_at_cadence() -> None:
    npc = AdminAudit(cadence_ticks=2, audit_path="/openapi.json")
    iface = _FakeInterface()
    npc.step(iface)
    npc.step(iface)
    npc.step(iface)
    npc.step(iface)
    # cadence=2: ticks 0, 2 → 2 calls.
    assert iface.calls == ["/openapi.json", "/openapi.json"]


def test_admin_audit_factory_defaults_to_openapi_json() -> None:
    npc = admin_audit_factory({})
    assert isinstance(npc, AdminAudit)
    iface = _FakeInterface()
    npc.step(iface)
    assert iface.calls == ["/openapi.json"]


def test_admin_audit_factory_honors_audit_path() -> None:
    npc = admin_audit_factory({"cadence_ticks": 1, "audit_path": "/internal/health"})
    iface = _FakeInterface()
    npc.step(iface)
    assert iface.calls == ["/internal/health"]


def test_admin_audit_swallows_errors() -> None:
    npc = AdminAudit(cadence_ticks=1)

    def boom(path: object) -> bytes:
        raise RuntimeError("denied")

    iface: dict[str, Any] = {"http_get": boom}
    npc.step(iface)  # must not raise


def test_admin_audit_rejects_empty_audit_path() -> None:
    with pytest.raises(ValueError, match="audit_path"):
        AdminAudit(audit_path="")


def test_admin_audit_factory_rejects_bad_path() -> None:
    with pytest.raises(ValueError, match="audit_path must be a string"):
        admin_audit_factory({"audit_path": 42})


# ---------------------------------------------------------------------------
# CuriousEmployee (LLM-backed agent NPC)
# ---------------------------------------------------------------------------


def test_curious_employee_factory_constructs_with_defaults() -> None:
    from cyber_webapp.npcs.curious_employee import CuriousEmployee
    from cyber_webapp.npcs.curious_employee import factory as ce_factory

    npc = ce_factory({})
    assert isinstance(npc, CuriousEmployee)
    assert npc.requires_llm is True
    assert npc._cadence_ticks == 5
    # No per-NPC backend by default; runtime supplies one via context.
    assert npc._backend_override is None
    assert "internal employee" in npc._system_prompt


def test_curious_employee_factory_promotes_model_to_strands_backend() -> None:
    """Per-NPC ``model`` config builds a StrandsAgentBackend override."""
    from cyber_webapp.npcs.curious_employee import CuriousEmployee
    from cyber_webapp.npcs.curious_employee import factory as ce_factory

    from openrange.agent_backend import StrandsAgentBackend

    npc = ce_factory(
        {
            "cadence_ticks": 2,
            "model": "claude-sonnet-4-20250514",
            "system_prompt": "You are a tester.",
        },
    )
    assert isinstance(npc, CuriousEmployee)
    assert npc._cadence_ticks == 2
    assert isinstance(npc._backend_override, StrandsAgentBackend)
    assert npc._backend_override._model == "claude-sonnet-4-20250514"
    assert npc._system_prompt == "You are a tester."


def test_curious_employee_factory_rejects_bad_config() -> None:
    from cyber_webapp.npcs.curious_employee import factory as ce_factory

    with pytest.raises(ValueError, match="cadence_ticks"):
        ce_factory({"cadence_ticks": "fast"})
    with pytest.raises(ValueError, match="model"):
        ce_factory({"model": 42})
    with pytest.raises(ValueError, match="system_prompt"):
        ce_factory({"system_prompt": ""})


def test_curious_employee_registered_via_entry_point() -> None:
    """The pack's pyproject.toml registers cyber.curious_employee."""
    from openrange.npc import NPCS

    assert "cyber.curious_employee" in NPCS.ids()


# ---------------------------------------------------------------------------
# OfficeChatter — scripted "person walking around the office" NPC
# ---------------------------------------------------------------------------


def test_office_chatter_factory_constructs_with_required_name() -> None:
    from cyber_webapp.npcs.office_chatter import OfficeChatter
    from cyber_webapp.npcs.office_chatter import factory as oc_factory

    npc = oc_factory({"name": "Alice"})
    assert isinstance(npc, OfficeChatter)
    assert npc.actor_id == "Alice"
    assert npc.requires_llm is False


def test_office_chatter_factory_rejects_bad_config() -> None:
    from cyber_webapp.npcs.office_chatter import factory as oc_factory

    with pytest.raises(ValueError, match="name"):
        oc_factory({})
    with pytest.raises(ValueError, match="cadence_ticks"):
        oc_factory({"name": "x", "cadence_ticks": "fast"})
    with pytest.raises(ValueError, match="lines"):
        oc_factory({"name": "x", "lines": "not-a-list"})
    with pytest.raises(ValueError, match="walk_probability"):
        oc_factory({"name": "x", "walk_probability": "high"})


def test_office_chatter_speaks_via_record_action() -> None:
    """A speech-only chatter publishes its line through record_action."""
    from cyber_webapp.npcs.office_chatter import OfficeChatter

    npc = OfficeChatter(
        name="Alice",
        cadence_ticks=1,
        lines=("morning",),
        walk_probability=0.0,  # always speak
        seed=1,
    )
    recorded: list[dict[str, Any]] = []

    def record(
        action: dict[str, Any],
        *,
        target: str | None = None,
        observation: object = None,
    ) -> None:
        recorded.append({"action": dict(action), "target": target})

    npc.start({"record_action": record})
    # start() publishes a presence event; cadence-driven speech follows.
    assert recorded[0]["action"] == {"present": True}
    npc.step({})
    npc.step({})
    npc.step({})
    speech = [e for e in recorded if e["action"] != {"present": True}]
    assert len(speech) == 3
    assert all(entry["action"] == {"speak": "morning"} for entry in speech)
    assert all(entry["target"] is None for entry in speech)


def test_office_chatter_walks_to_known_target() -> None:
    """When walk_probability is 1.0 and a home is set, every tick is a walk."""
    from cyber_webapp.npcs.office_chatter import OfficeChatter

    npc = OfficeChatter(
        name="Bob",
        cadence_ticks=1,
        home="svc-web",
        walk_probability=1.0,
        seed=1,
    )
    recorded: list[dict[str, Any]] = []

    def record(
        action: dict[str, Any],
        *,
        target: str | None = None,
        observation: object = None,
    ) -> None:
        recorded.append({"action": dict(action), "target": target})

    npc.start({"record_action": record})
    npc.step({})
    npc.step({})
    walks = [e for e in recorded if e["action"] != {"present": True}]
    assert all(entry["action"] == {"move": "wandering"} for entry in walks)
    assert all(entry["target"] == "svc-web" for entry in walks)


def test_office_chatter_obeys_cadence() -> None:
    from cyber_webapp.npcs.office_chatter import OfficeChatter

    npc = OfficeChatter(
        name="Carol",
        cadence_ticks=3,
        lines=("hi",),
        walk_probability=0.0,
        seed=1,
    )
    calls: list[dict[str, Any]] = []

    def record(
        action: dict[str, Any],
        *,
        target: str | None = None,
        observation: object = None,
    ) -> None:
        calls.append(dict(action))

    npc.start({"record_action": record})
    # Drop the start-time presence event; only step-driven actions
    # should be cadence-shaped. Initial cooldown is staggered (random
    # in [0, cadence_ticks)) so test against the expected count
    # within a 30-tick window: cadence=3 → 10 actions in 30 ticks
    # regardless of where the stagger lands.
    calls.clear()
    for _ in range(30):
        npc.step({})
    assert len(calls) == 10


def test_office_chatter_silent_without_record_action() -> None:
    """No record_action in context → NPC is a no-op, doesn't raise."""
    from cyber_webapp.npcs.office_chatter import OfficeChatter

    npc = OfficeChatter(name="Dave", cadence_ticks=1, seed=1)
    npc.start({})  # no record_action key
    npc.step({})  # must not raise
    npc.step({})


def test_office_chatter_registered_via_entry_point() -> None:
    from openrange.npc import NPCS

    assert "cyber.office_chatter" in NPCS.ids()
