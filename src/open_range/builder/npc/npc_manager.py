"""NPC traffic orchestrator.

Starts Level 0 shell-script traffic generators and (optionally) Level 1
LLM-driven NPC agents for a given snapshot.  Multimodal NPC channels
(chat, voice, document) are initialised at start and their activity logs
are available for SIEM consumption.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from open_range.builder.npc.channels import ChatChannel, DocumentChannel, VoiceChannel
from open_range.protocols import ContainerSet, SnapshotSpec

logger = logging.getLogger(__name__)

_SCRIPT_DIR = Path(__file__).parent


class NPCManager:
    """Start and stop NPC background traffic for a snapshot."""

    def __init__(self) -> None:
        self._processes: list[asyncio.subprocess.Process] = []
        self._tasks: list[asyncio.Task[Any]] = []
        self._running = False

        # Multimodal NPC communication channels
        self.channels: dict[str, ChatChannel | VoiceChannel | DocumentChannel] = {
            "chat": ChatChannel(),
            "voice": VoiceChannel(),
            "document": DocumentChannel(),
        }

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

        # Re-initialise channels for the new episode
        self.channels = {
            "chat": ChatChannel(),
            "voice": VoiceChannel(),
            "document": DocumentChannel(),
        }

        # Generate Level 0 chat traffic if personas are available
        if snapshot.npc_personas and len(snapshot.npc_personas) >= 2:
            from open_range.builder.npc.chat_traffic import generate_chat_traffic

            chat_ch = self.channels["chat"]
            assert isinstance(chat_ch, ChatChannel)
            generate_chat_traffic(
                personas=snapshot.npc_personas,
                channel=chat_ch,
                num_messages=10,
            )
            logger.info(
                "Generated %d chat messages for %d personas",
                len(chat_ch.get_channel_log()),
                len(snapshot.npc_personas),
            )

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

        # Clear channel state
        for ch in self.channels.values():
            ch.clear()

        self._running = False
        logger.info("All NPC traffic stopped.")

    @property
    def running(self) -> bool:
        """Whether NPC traffic is currently active."""
        return self._running

    def get_siem_log(self) -> list[dict[str, Any]]:
        """Aggregate activity logs from all channels for SIEM consumption."""
        logs: list[dict[str, Any]] = []
        chat_ch = self.channels.get("chat")
        if isinstance(chat_ch, ChatChannel):
            logs.extend(chat_ch.get_channel_log())
        voice_ch = self.channels.get("voice")
        if isinstance(voice_ch, VoiceChannel):
            logs.extend(voice_ch.get_call_log())
        doc_ch = self.channels.get("document")
        if isinstance(doc_ch, DocumentChannel):
            logs.extend(doc_ch.get_document_log())
        # Sort by timestamp
        logs.sort(key=lambda e: e.get("timestamp", 0))
        return logs
