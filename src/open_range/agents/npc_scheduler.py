"""NPC Agent-backed green scheduler for executing emergent npc behaviors."""

from __future__ import annotations

import collections
import logging
from math import floor
from typing import Any

from open_range.agents.npc_adapter import (
    configure_npc_llm,
    create_enterprise_world,
    parse_action,
    persona_to_npc,
)
from open_range.episode_config import EpisodeConfig
from open_range.green import GreenScheduler
from open_range.runtime_types import Action, RuntimeEvent
from open_range.snapshot import RuntimeSnapshot

logger = logging.getLogger(__name__)


class NPCGreenScheduler(GreenScheduler):
    """An npc green scheduler backed by logical npc agents and Kimi K2.

    This maps the time-stepping runtime loop directly to the NPC World
    and parses natural language actions back into OpenRange ``Action`` objects.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "moonshotai/kimi-k2-instruct",
        base_url: str = "https://integrate.api.nvidia.com/v1",
    ) -> None:
        self._snapshot: RuntimeSnapshot | None = None
        self._episode_config = EpisodeConfig()
        self._ready_actions: collections.deque[Action] = collections.deque()
        self._last_advanced_slot = -1

        self._npc_world: Any | None = None
        self._npc_agents: dict[str, Any] = {}
        self._event_buffer: list[RuntimeEvent] = []

        try:
            configure_npc_llm(api_key=api_key, model=model, base_url=base_url)
            self._available = True
        except ImportError:
            self._available = False
            logger.warning(
                "NPC framework dependencies not installed. NPCGreenScheduler will be a no-op."
            )

    def reset(self, snapshot: RuntimeSnapshot, episode_config: EpisodeConfig) -> None:
        self._snapshot = snapshot
        self._episode_config = episode_config
        self._ready_actions.clear()
        self._last_advanced_slot = -1
        self._event_buffer.clear()

        if (
            not self._available
            or not episode_config.green_enabled
            or episode_config.green_profile == "off"
        ):
            self._npc_world = None
            self._npc_agents = {}
            return

        personas = snapshot.world.green_personas
        if not personas:
            self._npc_world = None
            self._npc_agents = {}
            return

        # Initialize npc agents from personas
        self._npc_agents = {}
        for p in personas:
            agent = persona_to_npc(p)
            self._npc_agents[p.id] = agent

        # Create the simulation environment
        company_name = getattr(snapshot.world, "company_name", "enterprise")
        self._npc_world = create_enterprise_world(
            company_name, list(self._npc_agents.values())
        )

    def record_event(self, event: RuntimeEvent) -> None:
        if not self._npc_world or not self._episode_config.green_branch_enabled:
            return

        # Buffer events. We decide which agents observe what during `advance_until`.
        self._event_buffer.append(event)

    def advance_until(self, sim_time: float) -> None:
        if not self._npc_world:
            return

        goal_slot = max(0, floor(sim_time))
        if goal_slot <= self._last_advanced_slot:
            return

        # Push ONLY relevant observations natively to the NPC World
        if self._event_buffer:
            anomalies = [e for e in self._event_buffer if e.malicious or e.suspicious]
            if anomalies:
                # Let agents use their own cognition rather than us pre-digesting summaries artificially
                raw_logs = " | ".join(
                    f"{e.event_type} on {e.target_entity} from {e.actor}"
                    for e in anomalies
                )
                self._npc_world.broadcast(
                    f"Network telemetry observations: {raw_logs}"
                )

            self._event_buffer.clear()

        # Step the simulation for each slot passed
        steps_to_run = goal_slot - self._last_advanced_slot

        # We wrap the run to capture the natural language output of the agents
        self._npc_world.run(steps=steps_to_run)

        # Extract actions from agents' recent memory buffer directly via episodic memory
        for agent_id, agent in self._npc_agents.items():
            if not hasattr(agent, "episodic_memory"):
                continue

            # Retrieve only actions generated in the recent step horizons
            recent_episodes = agent.episodic_memory.retrieve_recent(n=5)
            for ep in recent_episodes:
                if isinstance(ep, dict) and ep.get("role") == "assistant":
                    content_obj = ep.get("content", {})
                    # TinyTroupe episodic memory maps the action schema internally
                    if isinstance(content_obj, dict) and "action" in content_obj:
                        inner = content_obj["action"]
                        # Extract the inner raw message string (often keyed as 'content' inside the memory buffer)
                        text_payload = inner.get("content", inner.get("msg", ""))
                        if text_payload:
                            parsed = parse_action(agent_id, text_payload)
                            if (
                                parsed.kind != "sleep"
                                and parsed not in self._ready_actions
                            ):
                                self._ready_actions.append(parsed)

        self._last_advanced_slot = goal_slot

    def pop_ready_actions(self) -> tuple[Action, ...]:
        actions = tuple(self._ready_actions)
        self._ready_actions.clear()
        return actions
