"""NPC manager: orchestrates multiple NPC agents through a workday."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from open_range.builder.npc.memory import MemoryStream
from open_range.builder.npc.npc_agent import LLMNPCAgent, NullNPCBehavior
from open_range.builder.npc.outbox import ActionOutbox, EventInbox, MailStore, SimClock
from open_range.builder.npc.persona import default_personas
from open_range.builder.npc.runtime_agent import RuntimeNPCAgent
from open_range.builder.npc.tasks import generate_tasks
from open_range.world_ir import GreenPersona

logger = logging.getLogger(__name__)


class NPCManager:
    """Start and stop a pool of NPC agents.

    In mock_mode the agents use NullNPCBehavior and no containers are
    required — useful for unit tests and dry-run validation.

    In online_mode, RuntimeNPCAgents are spawned with the outbox/inbox
    bridge so their actions flow into the runtime event stream.
    """

    def __init__(self, mock_mode: bool = False) -> None:
        self._mock_mode = mock_mode
        self._tasks: list[asyncio.Task[None]] = []
        self._running = False
        self._agents: list[RuntimeNPCAgent] = []

    @property
    def running(self) -> bool:
        return self._running

    @property
    def agents(self) -> list[RuntimeNPCAgent]:
        return list(self._agents)

    async def start(
        self,
        snapshot: Any,
        containers: Any = None,
        *,
        action_outbox: ActionOutbox | None = None,
        event_inboxes: dict[str, EventInbox] | None = None,
        sim_clock: SimClock | None = None,
        memory_streams: dict[str, MemoryStream] | None = None,
        mail_store: MailStore | None = None,
    ) -> None:
        """Spawn NPC agent tasks.

        When bridge components (outbox, inboxes, clock) are provided,
        RuntimeNPCAgents are used (online mode).  Otherwise falls back
        to the legacy LLMNPCAgent path or mock loop.
        """
        personas: list[GreenPersona] = (
            getattr(snapshot, "npc_personas", None)
            or getattr(getattr(snapshot, "world", None), "green_personas", None)
            or default_personas()
        )

        online = (
            action_outbox is not None
            and event_inboxes is not None
            and sim_clock is not None
        )

        self._agents = []
        for persona in personas:
            if self._mock_mode:
                task = asyncio.create_task(self._mock_loop(persona))
            elif online:
                assert action_outbox is not None
                assert event_inboxes is not None
                assert sim_clock is not None
                inbox = event_inboxes.get(persona.id, EventInbox())
                memory = (
                    memory_streams[persona.id]
                    if memory_streams and persona.id in memory_streams
                    else MemoryStream()
                )
                daily_tasks = generate_tasks(persona, list(personas))
                agent = RuntimeNPCAgent(
                    persona,
                    memory=memory,
                    outbox=action_outbox,
                    inbox=inbox,
                    clock=sim_clock,
                    tasks=daily_tasks,
                    colleagues=list(personas),
                    mail_store=mail_store,
                )
                self._agents.append(agent)
                task = asyncio.create_task(agent.run())
            else:
                agent_llm = LLMNPCAgent()
                task = asyncio.create_task(
                    agent_llm.run_loop(persona, containers, snapshot)
                )
            self._tasks.append(task)

        self._running = True
        if online:
            logger.info(
                "NPCManager started %d online agents — ensure "
                "green_branch_enabled=False in EpisodeConfig to avoid "
                "duplicate reactions from both scheduler and agents",
                len(self._agents),
            )
        else:
            logger.info(
                "NPCManager started %d agents (mock=%s)",
                len(self._tasks), self._mock_mode,
            )

    async def stop(self) -> None:
        """Cancel all NPC agent tasks."""
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._agents.clear()
        self._running = False
        logger.info("NPCManager stopped")

    async def _mock_loop(self, persona: Any) -> None:
        """Minimal no-op loop for mock mode."""
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
