"""NPC traffic orchestrator.

Starts Level 0 shell-script traffic generators and (optionally) Level 1
LLM-driven NPC agents for a given snapshot.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from open_range.protocols import ContainerSet, SnapshotSpec

logger = logging.getLogger(__name__)

_SCRIPT_DIR = Path(__file__).parent


class NPCManager:
    """Start and stop NPC background traffic for a snapshot."""

    def __init__(self) -> None:
        self._processes: list[asyncio.subprocess.Process] = []
        self._tasks: list[asyncio.Task[Any]] = []
        self._running = False

    async def start(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
    ) -> None:
        """Start NPC traffic generators.

        Level 0: shell scripts (http, ssh, db traffic loops).
        Level 1: LLM NPC agents (deferred to npc_agent.py).
        """
        if self._running:
            await self.stop()

        self._running = True
        npc_cfg = snapshot.npc_traffic

        # Determine which scripts to run
        scripts = npc_cfg.scripts or ["http_traffic.sh", "db_traffic.sh"]

        for script_name in scripts:
            script_path = _SCRIPT_DIR / script_name
            if not script_path.exists():
                logger.warning("NPC script not found: %s", script_path)
                continue

            # Build environment for the script
            env = {
                "WEB_HOST": "web",
                "DB_HOST": "db",
                "RATE_LAMBDA": str(int(npc_cfg.rate_lambda)),
            }

            logger.info("Starting NPC script: %s (rate=%s)", script_name, npc_cfg.rate_lambda)

            try:
                proc = await asyncio.create_subprocess_exec(
                    "bash",
                    str(script_path),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    env=env,
                )
                self._processes.append(proc)
            except OSError as exc:
                logger.warning("Failed to start NPC script %s: %s", script_name, exc)

        # Level 1 LLM NPCs -- start async agent loops if personas are present
        if npc_cfg.level >= 1 and snapshot.npc_personas:
            from open_range.builder.npc.npc_agent import LLMNPCAgent

            agent = LLMNPCAgent()
            for persona in snapshot.npc_personas:
                task = asyncio.create_task(
                    agent.run_loop(persona, containers),
                    name=f"npc_{persona.name}",
                )
                self._tasks.append(task)
                logger.info("Started LLM NPC agent: %s", persona.name)

    async def stop(self) -> None:
        """Stop all NPC traffic generators and agents."""
        # Cancel async NPC agent tasks
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        # Terminate shell script processes
        for proc in self._processes:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        self._processes.clear()

        self._running = False
        logger.info("All NPC traffic stopped.")

    @property
    def running(self) -> bool:
        """Whether NPC traffic is currently active."""
        return self._running
