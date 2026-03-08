"""NPC traffic orchestrator.

Starts Level 0 shell-script traffic generators and (optionally) Level 1
LLM-driven NPC agents for a given snapshot.  Multimodal NPC channels
(chat, voice, document) are initialised at start and their activity logs
are available for SIEM consumption.

In **mock mode** (``mock_mode=True``), no Docker exec or LLM calls are
made.  Only synthetic chat traffic is generated from the
``chat_traffic`` module, so unit tests can exercise the NPC pipeline
without infrastructure.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import Any

from open_range.builder.npc.channels import ChatChannel, DocumentChannel, VoiceChannel
from open_range.protocols import ContainerSet, SnapshotSpec

logger = logging.getLogger(__name__)

_SCRIPT_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Service keyword mappings used to match script prefixes to topology hosts
# and to resolve well-known env-var roles from service lists.
# ---------------------------------------------------------------------------

# Map a script filename keyword to service keywords that indicate a host
# can run that script.  Order matters for priority within each entry.
_SCRIPT_SERVICE_KEYWORDS: dict[str, list[str]] = {
    "http": ["nginx", "apache", "httpd", "web", "php-fpm"],
    "db": ["mysql", "mariadb", "postgres", "postgresql", "mongodb", "redis"],
    "ssh": ["nmap", "hydra", "nikto", "ssh-client", "attacker", "sshd"],
    "smtp": ["postfix", "sendmail", "exim", "dovecot", "mail"],
}

# Map an env-var role (e.g. WEB_HOST) to service keywords that identify the
# host fulfilling that role.
_ROLE_SERVICE_KEYWORDS: dict[str, list[str]] = {
    "WEB_HOST": ["nginx", "apache", "httpd", "web", "php-fpm"],
    "DB_HOST": ["mysql", "mariadb", "postgres", "postgresql", "mongodb"],
    "MAIL_HOST": ["postfix", "sendmail", "dovecot", "mail"],
    "LDAP_HOST": ["openldap", "ldap", "slapd"],
    "SIEM_HOST": ["rsyslog", "elasticsearch", "siem", "splunk"],
}


def _hosts_from_topology(topology: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the list of host dicts from *topology*, tolerating missing keys."""
    return topology.get("hosts") or []


def _host_matches_keywords(host: dict[str, Any], keywords: list[str]) -> bool:
    """Return True if the host's name or any of its services match *keywords*."""
    host_name = (host.get("name") or "").lower()
    services = [s.lower() for s in (host.get("services") or [])]
    for kw in keywords:
        kw_lower = kw.lower()
        if kw_lower in host_name or any(kw_lower in svc for svc in services):
            return True
    return False


def _container_for_script(script_name: str, topology: dict[str, Any]) -> str:
    """Determine which container a script should run inside.

    Matches the script filename against service keywords in the topology
    hosts.  Falls back to the first host if nothing matches.
    """
    hosts = _hosts_from_topology(topology)
    if not hosts:
        return "web"  # legacy fallback when topology is empty

    for prefix, keywords in _SCRIPT_SERVICE_KEYWORDS.items():
        if prefix in script_name.lower():
            for host in hosts:
                if _host_matches_keywords(host, keywords):
                    return host["name"]
            break  # prefix matched but no host found; fall through

    # Default: first host in topology
    return hosts[0].get("name", "web")


def _resolve_env_vars(topology: dict[str, Any], rate_lambda: float) -> dict[str, str]:
    """Build environment variables by resolving roles from the topology.

    Instead of hardcoding ``WEB_HOST=web``, this finds the host whose
    services list contains web/nginx/etc and maps the role to its name.
    """
    hosts = _hosts_from_topology(topology)
    env: dict[str, str] = {"RATE_LAMBDA": str(int(rate_lambda))}

    for role, keywords in _ROLE_SERVICE_KEYWORDS.items():
        for host in hosts:
            if _host_matches_keywords(host, keywords):
                env[role] = host["name"]
                break

    return env


def _derive_scripts_from_topology(topology: dict[str, Any]) -> list[str]:
    """Derive available NPC scripts from topology services.

    Scans the topology hosts and checks which script prefixes have a
    matching host.  Only returns scripts that actually exist on disk.
    """
    hosts = _hosts_from_topology(topology)
    scripts: list[str] = []

    for prefix, keywords in _SCRIPT_SERVICE_KEYWORDS.items():
        for host in hosts:
            if _host_matches_keywords(host, keywords):
                candidate = f"{prefix}_traffic.sh"
                if (_SCRIPT_DIR / candidate).exists():
                    scripts.append(candidate)
                break  # one match per prefix is enough

    return scripts


class NPCManager:
    """Start and stop NPC background traffic for a snapshot."""

    def __init__(self, mock_mode: bool = False) -> None:
        self._mock_mode = mock_mode
        self._processes: list[asyncio.subprocess.Process] = []
        self._tasks: list[asyncio.Task[Any]] = []
        self._running = False
        self._npc_agents: list[Any] = []  # LLMNPCAgent instances

        # Containers where scripts were deployed (for cleanup)
        self._script_containers: list[str] = []
        self._containers: ContainerSet | None = None

        # Multimodal NPC communication channels
        self.channels: dict[str, ChatChannel | VoiceChannel | DocumentChannel] = {
            "chat": ChatChannel(),
            "voice": VoiceChannel(),
            "document": DocumentChannel(),
        }

    # -----------------------------------------------------------------
    # Async start / stop (used when an event loop is available)
    # -----------------------------------------------------------------

    async def start(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet | None = None,
    ) -> None:
        """Start NPC traffic generators.

        Level 0: shell scripts (http, ssh, db traffic loops).
        Level 1: LLM NPC agents (deferred to npc_agent.py).

        In mock mode, only synthetic chat traffic is generated.
        """
        if self._running:
            await self.stop()

        self._running = True
        self._containers = containers
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

        # In mock mode, skip Docker exec and LLM agent loops
        if self._mock_mode:
            logger.info("NPC manager running in mock mode (no Docker/LLM)")
            return

        topology = snapshot.topology

        # Determine which scripts to run -- derive from topology when
        # the snapshot does not specify scripts explicitly.
        scripts = npc_cfg.scripts or _derive_scripts_from_topology(topology)

        # Resolve environment variables (WEB_HOST, DB_HOST, etc.) from
        # the topology instead of hardcoding host names.
        env_vars = _resolve_env_vars(topology, npc_cfg.rate_lambda)

        for script_name in scripts:
            script_path = _SCRIPT_DIR / script_name
            if not script_path.exists():
                logger.warning("NPC script not found: %s", script_path)
                continue

            container = _container_for_script(script_name, topology)
            logger.info(
                "Starting NPC script: %s in container %s (rate=%s)",
                script_name, container, npc_cfg.rate_lambda,
            )

            if containers is not None:
                # Run script inside the target container via docker exec
                try:
                    script_content = script_path.read_text()
                    encoded = base64.b64encode(script_content.encode()).decode()
                    env_prefix = " ".join(
                        f"{k}={v}" for k, v in env_vars.items()
                    )
                    await containers.exec(
                        container,
                        f"echo {encoded} | base64 -d > /tmp/{script_name} "
                        f"&& chmod +x /tmp/{script_name} "
                        f"&& {env_prefix} nohup bash /tmp/{script_name} "
                        f"> /dev/null 2>&1 &",
                    )
                    self._script_containers.append(container)
                except Exception as exc:
                    logger.warning(
                        "Failed to start NPC script %s in container %s: %s",
                        script_name, container, exc,
                    )
            else:
                # Fallback: run on host (original behavior)
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "bash",
                        str(script_path),
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                        env=env_vars,
                    )
                    self._processes.append(proc)
                except OSError as exc:
                    logger.warning("Failed to start NPC script %s: %s", script_name, exc)

        # Level 1 LLM NPCs -- start async agent loops if personas are present
        if npc_cfg.level >= 1 and snapshot.npc_personas and containers is not None:
            from open_range.builder.npc.npc_agent import LLMNPCAgent

            for persona in snapshot.npc_personas:
                agent = LLMNPCAgent()
                task = asyncio.create_task(
                    agent.run_loop(persona, containers),
                    name=f"npc_{persona.name}",
                )
                self._tasks.append(task)
                self._npc_agents.append(agent)
                logger.info("Started LLM NPC agent: %s", persona.name)

    async def stop(self) -> None:
        """Stop all NPC traffic generators and agents."""
        # Cancel async NPC agent tasks
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._npc_agents.clear()

        # Terminate shell script processes (host-mode fallback)
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

        # Kill background scripts inside containers
        if self._containers is not None:
            for container in set(self._script_containers):
                try:
                    await self._containers.exec(
                        container,
                        "pkill -f 'npc.*traffic' 2>/dev/null || true",
                    )
                except Exception:
                    pass
        self._script_containers.clear()
        self._containers = None

        # Clear channel state
        for ch in self.channels.values():
            ch.clear()

        self._running = False
        logger.info("All NPC traffic stopped.")

    # -----------------------------------------------------------------
    # Synchronous wrappers (for callers without an event loop)
    # -----------------------------------------------------------------

    def start_sync(self, snapshot: SnapshotSpec, containers: ContainerSet | None = None) -> None:
        """Synchronous wrapper around :meth:`start`.

        Uses the running event loop if available, otherwise creates a new one.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # We're inside an async context -- schedule and return.
            # Since we can't await here, run the coroutine eagerly using
            # loop.run_until_complete which won't work if a loop is running.
            # Instead, just call the sync-safe parts directly.
            self._start_sync_inner(snapshot, containers)
        else:
            asyncio.run(self.start(snapshot, containers))

    def stop_sync(self) -> None:
        """Synchronous wrapper around :meth:`stop`."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            self._stop_sync_inner()
        else:
            asyncio.run(self.stop())

    def _start_sync_inner(self, snapshot: SnapshotSpec, containers: ContainerSet | None = None) -> None:
        """Synchronous start that avoids asyncio for mock mode and chat traffic."""
        if self._running:
            self._stop_sync_inner()

        self._running = True
        self._containers = containers
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

        if self._mock_mode:
            logger.info("NPC manager running in mock mode (no Docker/LLM)")
            return

        # In live mode with an active event loop, schedule async start
        # for scripts and LLM agents. This is best-effort -- if it
        # fails, the chat traffic is already available.
        if containers is not None:
            logger.info(
                "NPC live scripts deferred (use async start() for full support)"
            )

    def _stop_sync_inner(self) -> None:
        """Synchronous stop for mock mode (no async cleanup needed)."""
        # Cancel any asyncio tasks that may exist
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        self._npc_agents.clear()
        self._processes.clear()
        self._script_containers.clear()
        self._containers = None

        for ch in self.channels.values():
            ch.clear()

        self._running = False

    # -----------------------------------------------------------------
    # Traffic log for reward computation
    # -----------------------------------------------------------------

    def get_traffic_log(self) -> list[dict[str, Any]]:
        """Return all NPC activity for reward computation.

        Combines SIEM channel logs with LLM NPC agent action logs.
        """
        logs = self.get_siem_log()

        # Append LLM NPC agent actions
        for agent in self._npc_agents:
            try:
                logs.extend(agent.get_actions())
            except Exception:
                pass

        logs.sort(key=lambda e: e.get("timestamp", 0))
        return logs

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
