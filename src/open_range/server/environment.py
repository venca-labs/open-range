"""RangeEnvironment -- OpenEnv Environment for the OpenRange cyber gymnasium.

Design:
- reset() selects a pre-validated snapshot from SnapshotStore (or accepts one via kwargs)
- step() routes commands via Docker SDK (docker exec)
- Red commands run on the attacker container (Kali tools available)
- Blue commands run on the siem container (monitoring/defense tools available)
- The container's installed tools are the natural constraint -- no artificial allowlists
- Red actions are logged so Blue's DetectionReward can score them
- Blue actions are logged so Red's StealthReward can score them
"""

from __future__ import annotations

import logging
import os
import re
import signal
import shlex
import socket
import subprocess as sp
import time
import urllib.request
from typing import TYPE_CHECKING, Any
from uuid import uuid4


def _install_zombie_reaper() -> None:
    """Install SIGCHLD handler to reap orphaned child processes.

    When Python runs as PID 1 (e.g. in Docker containers), it doesn't
    automatically reap zombie children.  This handler ensures service
    daemons started via subprocess don't accumulate as zombies.
    """
    def _reap_children(signum: int, frame: Any) -> None:
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                break

    signal.signal(signal.SIGCHLD, _reap_children)


# Install at import time so it's active before any service starts
if os.getpid() == 1:
    _install_zombie_reaper()

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import EnvironmentMetadata

from open_range.models import RangeAction, RangeObservation, RangeState
from open_range.protocols import ReadinessCheck, ServiceSpec, SnapshotSpec, TaskSpec

if TYPE_CHECKING:
    from open_range.server.compose_runner import BootedSnapshotProject
    from open_range.server.runtime import ManagedSnapshotRuntime

logger = logging.getLogger(__name__)

# Meta-commands processed by the environment itself (not forwarded to containers)
META_COMMANDS = {"submit_flag", "submit_evidence", "submit_finding", "auth", "logout"}

# Maximum steps before forced termination
DEFAULT_MAX_STEPS = 100

# Timeout for individual docker exec calls (seconds)
EXEC_TIMEOUT = 30.0

def _extract_command_name(command: str) -> str:
    """Extract the base command name from a full command string."""
    stripped = command.strip()
    if not stripped:
        return ""
    # Handle piped commands -- validate the first command
    first = stripped.split("|")[0].strip()
    # Handle environment variable prefixes
    parts = first.split()
    for part in parts:
        if "=" not in part:
            # Strip path prefix (e.g. /usr/bin/nmap -> nmap)
            return part.rsplit("/", 1)[-1]
    return parts[0] if parts else ""


_FINDING_TOKEN_RE = re.compile(r"[a-z0-9_./:-]{3,}")
_FINDING_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "then", "host",
    "user", "users", "detected", "detection", "attempt", "activity", "attack",
    "alert", "alerts", "found", "event", "events", "possible", "likely",
    "against", "into", "onto", "over", "under", "was", "were", "has", "have",
}
_ATTACK_SIGNAL_KEYWORDS = (
    "sqli", "sql injection", "xss", "path traversal", "command injection",
    "ssrf", "bruteforce", "brute force", "scan", "nmap", "nikto", "sqlmap",
    "hydra", "ldap injection", "smb enumeration", "phish", "phishing",
)


def _tokenize_finding_text(text: str) -> set[str]:
    tokens = {m.group(0).lower() for m in _FINDING_TOKEN_RE.finditer(text.lower())}
    return {token for token in tokens if token not in _FINDING_STOPWORDS}

class RangeEnvironment(Environment[RangeAction, RangeObservation, RangeState]):
    """OpenEnv Environment subclass for the cybersecurity range.

    Manages episode lifecycle, command routing, action tracking, and
    reward computation for Red/Blue tandem training.
    """

    SUPPORTS_CONCURRENT_SESSIONS = False

    def get_metadata(self) -> EnvironmentMetadata:
        """Return environment metadata for /metadata endpoint.

        Matches OpenEnv's EnvironmentMetadata schema.
        """
        return EnvironmentMetadata(
            name="open_range",
            version="0.1.0",
            description="Multi-agent cybersecurity gymnasium built on OpenEnv",
        )

    def __init__(
        self,
        runtime: "ManagedSnapshotRuntime | None" = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        exec_timeout: float = EXEC_TIMEOUT,
        docker_available: bool | None = None,
        execution_mode: str = "auto",
    ) -> None:
        super().__init__()
        self._state = RangeState()
        self._snapshot: SnapshotSpec | None = None
        self._snapshot_id: str | None = None
        self._red_history: list[dict[str, Any]] = []
        self._blue_history: list[dict[str, Any]] = []
        self._npc_traffic_log: list[dict[str, Any]] = []
        self._max_steps = max_steps
        self._exec_timeout = exec_timeout
        self._episode_start: float = 0.0

        # NPC manager -- started/stopped with episode lifecycle
        self._npc_manager: Any = None

        # Reward instances -- imported lazily to avoid circular deps
        self._red_reward: Any = None
        self._blue_reward: Any = None

        # Docker client -- resolved lazily
        self._docker_client: Any = None
        self._docker_available = docker_available
        self._runtime = runtime
        self._episode_recorded = False
        self._active_project: "BootedSnapshotProject | None" = None

        # Service PIDs tracked for subprocess mode lifecycle
        self._service_pids: list[int] = []

        # Zone router for subprocess mode enforcement
        self._zone_router: Any = None

        # Execution mode: "auto", "docker", or "subprocess"
        self._execution_mode = execution_mode

        # OPENRANGE_MOCK=1 forces mock mode (docker_available=False)
        if os.environ.get("OPENRANGE_MOCK") == "1" and docker_available is None:
            self._docker_available = False

        if execution_mode == "auto":
            env_mode = os.environ.get("OPENRANGE_EXECUTION_MODE", "")
            if env_mode:
                self._execution_mode = env_mode
            elif docker_available is False or self._docker_available is False:
                # Explicit docker_available=False (unit tests) → mock mode,
                # NOT subprocess. Keep execution_mode as "auto" so
                # _exec_in_container falls through to mock.
                self._execution_mode = "docker"
            elif self._get_docker() is not None:
                self._execution_mode = "docker"
            else:
                self._execution_mode = "subprocess"

    # -----------------------------------------------------------------
    # Docker helpers
    # -----------------------------------------------------------------

    def _get_docker(self) -> Any:
        """Lazy-load Docker client. Returns None if docker unavailable."""
        if self._docker_client is not None:
            return self._docker_client
        if self._docker_available is False:
            return None
        try:
            import docker

            self._docker_client = docker.from_env()
            self._docker_available = True
            return self._docker_client
        except Exception:
            self._docker_available = False
            logger.warning("Docker SDK unavailable -- running in mock mode")
            return None

    def _container_name(self, host: str) -> str:
        """Resolve logical host name to Docker container name.

        Tries multiple naming conventions:
        1. Snapshot compose config (if available)
        2. Docker Compose default: ``<project>-<service>-1``
        3. Raises ``RuntimeError`` if the host cannot be resolved

        In unit-test mock mode (docker_available=False, execution_mode="docker"),
        the bare hostname is returned as a fallback for test compatibility.
        """
        if self._snapshot and self._snapshot.compose:
            if (
                self._active_project is not None
                and host in self._active_project.containers.container_ids
            ):
                return self._active_project.containers.container_ids[host]
            services = self._snapshot.compose.get("services", {})
            if host in services:
                project = self._snapshot.compose.get(
                    "x-project-name", "openrange"
                )
                return f"{project}-{host}-1"

        # Try to discover the container by listing running containers
        client = self._get_docker()
        if client is not None:
            try:
                for container in client.containers.list():
                    name = container.name
                    if name == host or name.endswith(f"-{host}-1"):
                        return name
            except Exception:
                pass

        # In subprocess mode, commands run locally — the host name is only
        # used for logging/routing, not for Docker container lookup.
        if self._execution_mode == "subprocess":
            return host

        # In unit-test mock mode or when no containers are running,
        # return the bare hostname.  Execution will fail gracefully
        # (docker exec won't find the container → stderr returned).
        if self._docker_available is False and self._execution_mode == "docker":
            return host

        # Docker is reachable but no matching container exists — return bare
        # hostname so the exec layer can report the error in the observation
        # instead of crashing the API.
        logger.debug(
            "No running container found for host '%s'; returning bare name", host
        )
        return host

    def _exec_via_subprocess(self, host: str, command: str, timeout: float = 30.0) -> tuple[str, str]:
        """Execute a command via local subprocess (all-in-one container mode).

        All services run locally. Commands execute directly via bash.
        The host parameter is used for logging but commands run on localhost.
        """
        try:
            result = sp.run(
                ["bash", "-c", command],
                capture_output=True,
                timeout=timeout,
                text=True,
            )
            return result.stdout, result.stderr
        except sp.TimeoutExpired:
            return "", f"Command timed out after {timeout}s"
        except Exception as exc:
            return "", f"Execution error: {exc}"

    def _exec_in_container(
        self,
        container_name: str,
        command: str,
        timeout_s: float | None = None,
    ) -> tuple[str, str]:
        """Execute a command inside a Docker container.

        Returns (stdout, stderr). Routes based on execution_mode:
        - "subprocess": runs via local bash
        - "docker": runs via Docker SDK
        - Falls back to mock when docker_available is explicitly False
          (unit test backward compatibility).
        """
        # Subprocess execution mode
        if self._execution_mode == "subprocess":
            return self._exec_via_subprocess(
                container_name,
                command,
                timeout_s if timeout_s is not None else self._exec_timeout,
            )

        # Unit-test backward compatibility: when docker_available was explicitly
        # set to False AND execution_mode resolved to "docker" (the auto path
        # for tests), return synthetic output so tests can assert on container
        # routing without real Docker.
        if self._docker_available is False:
            if self._execution_mode == "docker":
                return (
                    f"[mock] executed on {container_name}: {command}",
                    "",
                )
            # Production path: docker unavailable and mode is not subprocess
            return "", f"Docker unavailable (execution_mode={self._execution_mode})"

        # Docker execution mode
        client = self._get_docker()
        if client is None:
            return "", "Docker unavailable and execution_mode is not 'subprocess'"
        try:
            container = client.containers.get(container_name)
            if timeout_s is not None:
                try:
                    result = sp.run(
                        ["docker", "exec", container.name, "sh", "-c", command],
                        capture_output=True,
                        timeout=timeout_s,
                        text=True,
                        check=False,
                    )
                    return result.stdout, result.stderr
                except sp.TimeoutExpired:
                    return "", f"Command timed out after {timeout_s}s"

            result = container.exec_run(
                ["sh", "-c", command],
                demux=True,
            )
            stdout = (result.output[0] or b"").decode(errors="replace") if result.output else ""
            stderr = (result.output[1] or b"").decode(errors="replace") if result.output else ""
            return stdout, stderr
        except Exception as exc:
            return "", f"Error executing command: {exc}"

    # -----------------------------------------------------------------
    # Database credential helpers
    # -----------------------------------------------------------------

    def _db_credentials(self) -> str:
        """Build MySQL CLI credential flags from the snapshot topology.

        Looks up users in ``self._snapshot.topology["users"]`` whose ``hosts``
        list contains ``"db"``. Returns ``-u <user> -p<password>`` for the
        first match, or ``-u root`` (no password) if no user is defined.
        """
        if self._snapshot and isinstance(self._snapshot.topology, dict):
            users = self._snapshot.topology.get("users", [])
            for user in users:
                hosts = user.get("hosts", [])
                if "db" in hosts:
                    uname = user.get("username", "root")
                    pwd = user.get("password", "")
                    if pwd:
                        return f"-u {uname} -p{pwd}"
                    return f"-u {uname}"
        return "-u root"

    # -----------------------------------------------------------------
    # Snapshot applicator — deploys files, flags, and SQL to containers
    # -----------------------------------------------------------------

    def _apply_snapshot(self, snapshot: SnapshotSpec) -> None:
        """Deploy snapshot artifacts (files, SQL, flags) to running containers.

        Parses the ``files`` dict from the snapshot spec. Keys use the format
        ``<container>:<path>`` for file deployments and ``db:sql`` for SQL
        statements. Creates parent directories as needed.

        In subprocess mode, files are written directly to disk and SQL is
        executed via the local ``mysql`` CLI.
        """
        if self._execution_mode == "subprocess":
            self._apply_snapshot_subprocess(snapshot)
            return

        client = self._get_docker()
        if client is None:
            logger.info("Docker unavailable — skipping snapshot application")
            return

        if not snapshot.files:
            logger.info("No files in snapshot to deploy")
            return

        import base64

        deployed = 0
        for key, content in snapshot.files.items():
            try:
                if key == "db:sql":
                    container_name = self._container_name("db")
                    b64 = base64.b64encode(content.encode()).decode()
                    self._exec_in_container(
                        container_name,
                        f"echo '{b64}' | base64 -d > /tmp/_snapshot.sql",
                    )
                    db_creds = self._db_credentials()
                    _, stderr = self._exec_in_container(
                        container_name,
                        f"mysql {db_creds} < /tmp/_snapshot.sql",
                    )
                    self._exec_in_container(
                        container_name, "rm -f /tmp/_snapshot.sql"
                    )
                    if stderr and "ERROR" in stderr:
                        logger.warning("SQL deployment error: %s", stderr)
                    else:
                        deployed += 1
                        logger.info("Deployed SQL to db")
                    continue

                if ":" not in key:
                    logger.warning("Skipping file with bad key format: %s", key)
                    continue

                container, path = key.split(":", 1)
                container_name = self._container_name(container)

                parent_dir = path.rsplit("/", 1)[0] if "/" in path else "/"
                self._exec_in_container(
                    container_name, f"mkdir -p {shlex.quote(parent_dir)}"
                )

                b64 = base64.b64encode(content.encode()).decode()
                cmd = f"echo '{b64}' | base64 -d > {shlex.quote(path)}"
                _, stderr = self._exec_in_container(container_name, cmd)
                if stderr and "Error" in stderr:
                    logger.warning(
                        "File deployment error for %s: %s", key, stderr
                    )
                else:
                    deployed += 1
                    logger.info("Deployed file: %s:%s", container, path)

            except Exception as exc:
                logger.warning("Failed to deploy %s: %s", key, exc)

        logger.info(
            "Snapshot application complete: %d/%d artifacts deployed",
            deployed, len(snapshot.files),
        )

    def _apply_snapshot_subprocess(self, snapshot: SnapshotSpec) -> None:
        """Deploy snapshot artifacts directly to the local filesystem.

        Used in subprocess execution mode where all services run locally.
        SQL statements are written to a temp file and executed via ``mysql`` CLI.
        Regular files are written directly to their target paths.
        """
        if not snapshot.files:
            logger.info("No files in snapshot to deploy")
            return

        import tempfile

        deployed = 0
        for key, content in snapshot.files.items():
            try:
                if key == "db:sql":
                    # Auto-create databases referenced by USE statements
                    import re

                    db_names = re.findall(r"(?i)USE\s+(\w+)\s*;", content)
                    preamble = ""
                    for db in dict.fromkeys(db_names):  # dedupe, preserve order
                        preamble += f"CREATE DATABASE IF NOT EXISTS `{db}`;\n"
                    sql_content = preamble + content

                    # Write SQL to temp file, execute via mysql CLI
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".sql", delete=False
                    ) as tmp:
                        tmp.write(sql_content)
                        tmp_path = tmp.name
                    try:
                        db_creds = self._db_credentials()
                        _, stderr = self._exec_via_subprocess(
                            "db",
                            f"mysql {db_creds} < {shlex.quote(tmp_path)}",
                            timeout=self._exec_timeout,
                        )
                        if stderr and "ERROR" in stderr:
                            logger.warning("SQL deployment error: %s", stderr)
                        else:
                            deployed += 1
                            logger.info("Deployed SQL to db (subprocess)")
                    finally:
                        os.unlink(tmp_path)
                    continue

                if ":" not in key:
                    logger.warning("Skipping file with bad key format: %s", key)
                    continue

                _container, path = key.split(":", 1)

                # Create parent directory and write file directly
                parent_dir = os.path.dirname(path) if os.path.dirname(path) else "/"
                os.makedirs(parent_dir, exist_ok=True)

                with open(path, "w") as f:
                    f.write(content)
                deployed += 1
                logger.info("Deployed file (subprocess): %s:%s", _container, path)

            except Exception as exc:
                logger.warning("Failed to deploy %s: %s", key, exc)

        logger.info(
            "Snapshot application complete (subprocess): %d/%d artifacts deployed",
            deployed, len(snapshot.files),
        )

    # -----------------------------------------------------------------
    # Service lifecycle (subprocess mode)
    # -----------------------------------------------------------------

    def _stop_services(self) -> None:
        """Stop services started by a previous episode.

        Derives daemon names from the snapshot's ``services`` list.
        """
        if self._execution_mode != "subprocess":
            return

        import signal

        # Kill tracked PIDs first
        for pid in self._service_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug("Failed to stop PID %d: %s", pid, exc)

        daemon_names: list[str] = []
        if self._snapshot and self._snapshot.services:
            for svc in self._snapshot.services:
                name = svc.daemon.split("/")[-1].split()[0]
                if name and name not in daemon_names:
                    daemon_names.append(name)

        for daemon_name in daemon_names:
            try:
                sp.run(
                    ["pkill", "-x", daemon_name],
                    capture_output=True,
                    timeout=5,
                    text=True,
                    check=False,
                )
            except Exception as exc:
                logger.debug("Failed to stop daemon %s: %s", daemon_name, exc)

        self._service_pids = []
        logger.info("Stopped previous episode services")

    def _start_snapshot_services(self, snapshot: SnapshotSpec) -> None:
        """Start services based on snapshot spec (subprocess mode only).

        The snapshot's ``services`` list is normally populated by the renderer.
        Snapshots without explicit service specs skip subprocess provisioning.
        """
        if self._execution_mode != "subprocess":
            return

        if snapshot.services:
            self._start_services_from_specs(snapshot.services)
        else:
            logger.info("No service specs in snapshot -- skipping service provisioning")

    def _start_services_from_specs(self, services: list[ServiceSpec]) -> None:
        """Start a list of :class:`ServiceSpec` entries generically."""
        for candidate in ("/var/log/siem/consolidated", "/tmp/openrange/siem/consolidated"):
            try:
                os.makedirs(candidate, exist_ok=True)
                break
            except PermissionError:
                continue

        started: list[str] = []
        for svc in services:
            try:
                self._start_service(svc)
                started.append(svc.daemon)
            except Exception as exc:
                logger.warning(
                    "Failed to start service %s (host=%s): %s",
                    svc.daemon, svc.host, exc,
                )

        # Capture PIDs of started service processes
        self._capture_service_pids()
        logger.info(
            "Service provisioning complete (spec-driven): %s",
            ", ".join(started) or "none",
        )

    def _start_service(self, svc: ServiceSpec) -> None:
        """Run init commands, start daemon, wait for readiness."""
        logger.info("Starting service: %s (host=%s)", svc.daemon, svc.host)

        # Set env vars
        env = os.environ.copy()
        env.update(svc.env_vars)

        original_log_dir = svc.log_dir or "/var/log/siem"
        log_dir = original_log_dir
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            if original_log_dir.startswith("/var/log/"):
                log_dir = os.path.join(
                    "/tmp/openrange",
                    original_log_dir.removeprefix("/var/log/"),
                )
            else:
                log_dir = os.path.join("/tmp/openrange", original_log_dir.strip("/"))
            os.makedirs(log_dir, exist_ok=True)

        init_commands = [
            cmd.replace(original_log_dir, log_dir)
            if original_log_dir and original_log_dir != log_dir
            else cmd
            for cmd in svc.init_commands
        ]
        start_command = (
            svc.start_command.replace(original_log_dir, log_dir)
            if original_log_dir and original_log_dir != log_dir
            else svc.start_command
        )

        # Run init commands (isolated from PID 1's process group)
        for cmd in init_commands:
            try:
                result = sp.run(
                    ["bash", "-c", cmd],
                    capture_output=True,
                    timeout=30,
                    text=True,
                    env=env,
                    check=False,
                    start_new_session=True,
                )
                if result.returncode != 0 and result.stderr:
                    logger.debug(
                        "Init cmd stderr for %s: %s",
                        svc.daemon, result.stderr[:200],
                    )
            except Exception as exc:
                logger.warning("Init command failed for %s: %s", svc.daemon, exc)

        # Start the daemon in a new session so it cannot send signals to
        # PID 1 (uvicorn).  Ensure the command is backgrounded.
        effective_cmd = start_command
        if not effective_cmd.rstrip().endswith("&"):
            effective_cmd = f"({effective_cmd}) &"
        try:
            result = sp.run(
                ["bash", "-c", effective_cmd],
                capture_output=True,
                timeout=30,
                text=True,
                env=env,
                check=False,
                start_new_session=True,
            )
            if result.returncode != 0 and result.stderr:
                logger.debug(
                    "Start cmd stderr for %s: %s",
                    svc.daemon, result.stderr[:200],
                )
        except Exception as exc:
            logger.warning("Start command failed for %s: %s", svc.daemon, exc)
            return

        # Wait for readiness
        self._wait_for_readiness(svc)

    def _wait_for_readiness(self, svc: ServiceSpec) -> None:
        """Poll the readiness check until success or timeout."""
        check = svc.readiness
        if check.type == "tcp" and check.port == 0 and not check.url and not check.command:
            logger.info("  %s: started (no readiness check)", svc.daemon)
            return

        max_attempts = max(int(check.timeout_s / max(check.interval_s, 0.1)), 1)
        for attempt in range(max_attempts):
            if self._probe_readiness(check):
                logger.info("  %s: ready (%ds)", svc.daemon, attempt + 1)
                return
            time.sleep(check.interval_s)

        logger.warning("  %s: readiness timeout after %ds", svc.daemon, check.timeout_s)

    @staticmethod
    def _probe_readiness(check: ReadinessCheck) -> bool:
        """Execute a single readiness probe. Returns True on success."""
        try:
            if check.type == "tcp" and check.port > 0:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect(("127.0.0.1", check.port))
                return True
            elif check.type == "http" and check.url:
                result = sp.run(
                    ["curl", "-sf", check.url],
                    capture_output=True, timeout=3,
                )
                return result.returncode == 0
            elif check.type == "command" and check.command:
                result = sp.run(
                    ["bash", "-c", check.command],
                    capture_output=True, timeout=5,
                )
                return result.returncode == 0
        except Exception:
            pass
        return False

    def _capture_service_pids(self) -> None:
        """Capture PIDs of running service processes."""
        self._service_pids = []
        daemon_names: list[str] = []
        if self._snapshot and self._snapshot.services:
            for svc in self._snapshot.services:
                name = svc.daemon.split("/")[-1].split()[0]
                if name and name not in daemon_names:
                    daemon_names.append(name)

        for daemon_name in daemon_names:
            try:
                result = sp.run(
                    ["pgrep", "-x", daemon_name],
                    capture_output=True, timeout=5, text=True, check=False,
                )
            except Exception:
                continue
            for line in result.stdout.splitlines():
                pid = line.strip()
                if pid.isdigit():
                    self._service_pids.append(int(pid))

    def _build_container_set(self) -> "ContainerSet | None":
        """Build a ContainerSet from running Docker containers.

        Returns None when Docker is unavailable or no containers are found.
        """
        from open_range.protocols import ContainerSet

        client = self._get_docker()
        if client is None:
            return None

        container_ids: dict[str, str] = {}
        try:
            for container in client.containers.list():
                name = container.name
                # Map service name to container id (open-range-web-1 → web)
                for suffix in ("-1",):
                    if name.endswith(suffix):
                        svc = name.rsplit("-", 1)[0]  # open-range-web
                        svc = svc.rsplit("-", 1)[-1]   # web
                        container_ids[svc] = name
                        break
                else:
                    container_ids[name] = name
        except Exception as exc:
            logger.debug("Container discovery failed: %s", exc)
            return None

        if not container_ids:
            return None

        project = "open-range"
        if self._snapshot and self._snapshot.compose:
            project = self._snapshot.compose.get("x-project-name", project)

        return ContainerSet(project_name=project, container_ids=container_ids)

    def _start_npcs(self, snapshot: SnapshotSpec) -> None:
        """Start NPC traffic generators for the current episode.

        When execution_mode is not "docker" or Docker is unavailable, only
        synthetic chat traffic is generated (no Docker exec or LLM calls).
        In live mode, shell scripts run inside containers and LLM NPC
        agents poll for stimuli.
        """
        try:
            self._stop_npcs()

            from open_range.builder.npc.npc_manager import NPCManager

            mock = (self._docker_available is False) or (self._execution_mode != "docker")
            npc_model = os.environ.get("OPENRANGE_NPC_MODEL")
            mgr = NPCManager(mock_mode=mock, model=npc_model)
            self._npc_manager = mgr

            # Build ContainerSet for live Docker mode
            containers = None if mock else self._build_container_set()

            # Start synchronously (NPCManager.start_sync handles mock vs live)
            mgr.start_sync(snapshot, containers)

            # Seed the traffic log immediately from chat traffic generated at
            # start time so that Blue has NPC noise from step 1.
            self._refresh_npc_traffic_log()

            logger.info(
                "NPC manager started (mock=%s, containers=%s, personas=%d)",
                mock,
                bool(containers),
                len(snapshot.npc_personas or []),
            )
        except Exception as exc:
            logger.warning("NPC startup failed (non-fatal): %s", exc)
            self._npc_manager = None

    def _stop_npcs(self) -> None:
        """Stop any running NPC traffic generators."""
        if self._npc_manager is not None:
            try:
                self._npc_manager.stop_sync()
            except Exception as exc:
                logger.debug("NPC stop error (ignored): %s", exc)
            self._npc_manager = None

    def _teardown_active_project(self) -> None:
        """Tear down the currently active runtime-backed episode project."""
        if self._active_project is None:
            return
        project = self._active_project
        self._active_project = None
        if self._runtime is None:
            return
        try:
            self._runtime.teardown_snapshot_project(project)
        except Exception as exc:
            logger.warning(
                "Failed to tear down active snapshot project %s: %s",
                project.project_name,
                exc,
            )

    def _activate_runtime_snapshot(
        self,
        snapshot: SnapshotSpec,
        *,
        episode_id: str,
    ) -> bool:
        """Boot a clean project for a runtime-backed admitted snapshot.

        Returns True when the snapshot was activated through the managed
        runtime and no overlay deployment is needed in-process.
        """
        if self._runtime is None or not self._snapshot_id:
            return False
        if self._execution_mode != "docker":
            return False
        if self._get_docker() is None:
            return False

        project = self._runtime.activate_snapshot_project(
            snapshot_id=self._snapshot_id,
            snapshot=snapshot,
            episode_id=episode_id,
        )
        self._active_project = project
        compose = dict(snapshot.compose)
        compose["x-project-name"] = project.project_name
        snapshot.compose = compose
        return True

    def _refresh_npc_traffic_log(self) -> None:
        """Pull latest NPC activity from the manager into the traffic log."""
        if self._npc_manager is not None:
            try:
                self._npc_traffic_log = self._npc_manager.get_traffic_log()
            except Exception as exc:
                logger.debug("NPC traffic log refresh failed: %s", exc)

    def _publish_console_state(self) -> None:
        """Publish the latest snapshot/state to the operator console."""
        try:
            from open_range.server.console import publish_episode

            publish_episode(self._snapshot, self._state)
        except Exception:
            pass

    # -----------------------------------------------------------------
    # Snapshot selection
    # -----------------------------------------------------------------

    def _select_snapshot(self, **kwargs: Any) -> SnapshotSpec:
        """Select or accept a snapshot for the episode.

        Priority:
        1. Explicit snapshot passed via kwargs["snapshot"]
        2. Snapshot loaded from store via kwargs["snapshot_id"]
        3. A minimal fallback (for testing without Docker)
        """
        if "snapshot" in kwargs and isinstance(kwargs["snapshot"], SnapshotSpec):
            self._snapshot_id = kwargs.get("snapshot_id")
            snap = kwargs["snapshot"]
        elif self._runtime is not None:
            if "snapshot_id" in kwargs and kwargs["snapshot_id"]:
                admitted = self._runtime.get_snapshot(str(kwargs["snapshot_id"]))
            else:
                admitted = self._runtime.acquire_snapshot()
            self._snapshot_id = admitted.snapshot_id
            snap = admitted.snapshot
        else:
            self._snapshot_id = None
            snap = SnapshotSpec(
                topology={"hosts": ["attacker", "siem"]},
                flags=[],
                golden_path=[],
                task={
                    "red_briefing": "Test mode.",
                    "blue_briefing": "Test mode.",
                },
            )

        # Defensive: ensure required fields are not None
        if snap.flags is None:
            snap.flags = []
        if snap.topology is None:
            snap.topology = {}
        if snap.task is None:
            snap.task = {}

        return snap

    # -----------------------------------------------------------------
    # Special command handling
    # -----------------------------------------------------------------

    def _is_finding_grounded(self, finding: str) -> bool:
        """Infer whether a Blue finding is grounded in observed Red activity."""
        content = (finding or "").strip().lower()
        if not content:
            return False

        red_actions = [
            record
            for record in self._red_history
            if record.get("type") not in ("hallucinated_flag", "evidence")
        ]
        if not red_actions:
            return False

        cmd_names = {
            str(record.get("cmd_name", "")).lower()
            for record in red_actions
            if record.get("cmd_name")
        }
        if any(cmd and cmd in content for cmd in cmd_names):
            return True

        finding_tokens = _tokenize_finding_text(content)
        if not finding_tokens:
            return False

        red_tokens: set[str] = set()
        for record in red_actions:
            red_tokens.update(_tokenize_finding_text(str(record.get("command", ""))))
            red_tokens.update(_tokenize_finding_text(str(record.get("target", ""))))
            cmd_name = str(record.get("cmd_name", "")).lower()
            if cmd_name:
                red_tokens.add(cmd_name)

        overlap = finding_tokens & red_tokens
        if len(overlap) >= 2:
            return True

        has_attack_signal = any(keyword in content for keyword in _ATTACK_SIGNAL_KEYWORDS)
        return has_attack_signal and len(overlap) >= 1

    def _handle_submit_flag(self, action: RangeAction) -> RangeObservation:
        """Process a submit_flag command from Red."""
        # Extract flag value from command: submit_flag FLAG{...}
        parts = action.command.strip().split(maxsplit=1)
        submitted = parts[1].strip() if len(parts) > 1 else ""

        if not self._snapshot:
            return RangeObservation(
                stdout="No active snapshot",
                stderr="",
                done=True,
            )

        valid_flags = {f.value for f in self._snapshot.flags} if self._snapshot.flags else set()
        already_found = set(self._state.flags_found)

        if submitted in valid_flags and submitted not in already_found:
            self._state.flags_found.append(submitted)
            # Check if all flags captured
            all_captured = valid_flags and set(self._state.flags_found) == valid_flags
            return RangeObservation(
                stdout=f"Correct! Flag accepted: {submitted}",
                flags_captured=[submitted],
                done=all_captured,
            )
        elif submitted in already_found:
            return RangeObservation(
                stdout=f"Flag already submitted: {submitted}",
            )
        else:
            # Hallucinated flag -- tracked for penalty
            self._red_history.append({
                "step": self._state.step_count,
                "type": "hallucinated_flag",
                "value": submitted,
                "time": time.time(),
            })
            return RangeObservation(
                stdout=f"Invalid flag: {submitted}",
                stderr="Flag does not match any known flag in this range.",
            )

    def _handle_submit_evidence(self, action: RangeAction) -> RangeObservation:
        """Process a submit_evidence command from Red."""
        parts = action.command.strip().split(maxsplit=1)
        evidence = parts[1] if len(parts) > 1 else ""
        self._red_history.append({
            "step": self._state.step_count,
            "type": "evidence",
            "content": evidence,
            "time": time.time(),
        })
        return RangeObservation(
            stdout="Evidence submitted and recorded.",
        )

    def _handle_submit_finding(self, action: RangeAction) -> RangeObservation:
        """Process a submit_finding command from Blue."""
        parts = action.command.strip().split(maxsplit=1)
        finding = parts[1] if len(parts) > 1 else ""
        grounded = self._is_finding_grounded(finding)
        self._blue_history.append({
            "step": self._state.step_count,
            "type": "finding",
            "content": finding,
            "grounded": grounded,
            "time": time.time(),
        })
        return RangeObservation(
            stdout="Finding submitted and recorded.",
        )

    # -----------------------------------------------------------------
    # Auth scenario (#25)
    # -----------------------------------------------------------------

    def _handle_auth(self, action: RangeAction) -> RangeObservation:
        """Process an ``auth <host> <username> <password>`` command.

        Checks credentials against the topology user list in the snapshot.
        Successful auth is recorded in ``state.active_sessions``.
        """
        parts = action.command.strip().split(maxsplit=3)
        if len(parts) < 4:
            return RangeObservation(
                stdout="",
                stderr="Usage: auth <host> <username> <password>",
            )
        host = parts[1]
        username = parts[2]
        password = parts[3]

        attempt = {
            "step": self._state.step_count,
            "host": host,
            "username": username,
            "success": False,
            "time": time.time(),
        }

        # Lookup credentials in the snapshot topology
        authenticated = False
        if self._snapshot and isinstance(self._snapshot.topology, dict):
            users = self._snapshot.topology.get("users", [])
            for user in users:
                if (
                    user.get("username") == username
                    and user.get("password") == password
                    and host in user.get("hosts", [])
                ):
                    authenticated = True
                    break

        attempt["success"] = authenticated
        self._state.auth_attempts.append(attempt)

        if authenticated:
            self._state.active_sessions[host] = username
            # Record access grant for pivot tracking
            grant = f"{host}:shell"
            if grant not in self._state.access_grants:
                self._state.access_grants.append(grant)
            return RangeObservation(
                stdout=f"Authenticated as {username} on {host}.",
            )
        else:
            return RangeObservation(
                stdout="",
                stderr=f"Authentication failed for {username} on {host}.",
            )

    def _handle_logout(self, action: RangeAction) -> RangeObservation:
        """Process a ``logout <host>`` command."""
        parts = action.command.strip().split()
        if len(parts) < 2:
            return RangeObservation(
                stdout="",
                stderr="Usage: logout <host>",
            )
        host = parts[1]

        if host in self._state.active_sessions:
            user = self._state.active_sessions.pop(host)
            return RangeObservation(
                stdout=f"Logged out {user} from {host}.",
            )
        else:
            return RangeObservation(
                stdout="",
                stderr=f"No active session on {host}.",
            )

    # -----------------------------------------------------------------
    # Milestone checking (#17 task engine)
    # -----------------------------------------------------------------

    def _check_milestone(self, output: str) -> str | None:
        """Check if command output satisfies the next pending milestone.

        Returns the milestone string if matched, None otherwise.
        """
        if not self._snapshot:
            return None

        task = self._snapshot.task
        if isinstance(task, dict):
            task_type = task.get("task_type", "exploit")
            milestones = task.get("milestones", [])
        elif isinstance(task, TaskSpec):
            task_type = task.task_type
            milestones = task.milestones
        else:
            return None

        if task_type != "multi_step" or not milestones:
            return None

        # Check each incomplete milestone against the output
        completed = set(self._state.milestones_completed)
        for ms in milestones:
            if ms not in completed and ms.lower() in output.lower():
                return ms
        return None

    # -----------------------------------------------------------------
    # Pivot mechanics (#26)
    # -----------------------------------------------------------------

    def _check_pivot(self, action: RangeAction, stdout: str) -> None:
        """Detect credential or access token leaks in command output.

        When output contains credentials that match the truth graph,
        record an access grant and log the pivot event.
        """
        if not self._snapshot or not isinstance(self._snapshot.topology, dict):
            return

        users = self._snapshot.topology.get("users", [])
        for user in users:
            uname = user.get("username", "")
            pwd = user.get("password", "")
            if not uname or not pwd:
                continue
            # Check if credentials appear in the command output
            if uname in stdout and pwd in stdout:
                for host in user.get("hosts", []):
                    grant = f"{host}:credential"
                    if grant not in self._state.access_grants:
                        self._state.access_grants.append(grant)
                        # Determine source host from the action target
                        source = self._resolve_target(action)
                        self._state.pivot_history.append({
                            "from": source,
                            "to": host,
                            "via": "credential_reuse",
                            "username": uname,
                        })

    # -----------------------------------------------------------------
    # Target resolution
    # -----------------------------------------------------------------

    def _resolve_target(self, action: RangeAction) -> str:
        """Determine which container to route the command to.

        Reads from the snapshot topology to find the appropriate host:
        - Red: host with role=attacker or zone=external
        - Blue: host with role=siem or zone=management

        Resolution priority:
        1. host_catalog metadata (compiled from manifest)
        2. dict entries in topology["hosts"] with role/zone
        3. literal host-name match ("attacker"/"siem")
        4. zone membership fallback via topology["zones"]
        5. positional fallback (first host for Red, last for Blue)
        """
        if not self._snapshot or not isinstance(self._snapshot.topology, dict):
            raise RuntimeError("Cannot resolve target — no snapshot topology loaded")

        topology = self._snapshot.topology
        hosts = topology.get("hosts", [])
        if not hosts:
            raise RuntimeError("Cannot resolve target — snapshot topology has no hosts")

        target_role = "attacker" if action.mode == "red" else "siem"
        target_zone = "external" if action.mode == "red" else "management"

        host_catalog = topology.get("host_catalog", {})
        if isinstance(host_catalog, dict):
            for host_name, meta in host_catalog.items():
                if not isinstance(meta, dict):
                    continue
                if meta.get("role") == target_role or meta.get("zone") == target_zone:
                    if host_name:
                        return self._container_name(str(host_name))

        # Look for a host with matching role or zone
        for h in hosts:
            if isinstance(h, dict):
                if h.get("role") == target_role or h.get("zone") == target_zone:
                    host_name = h.get("name", h.get("hostname", ""))
                    if host_name:
                        return self._container_name(host_name)

        # String host list: match by name
        for h in hosts:
            name = h if isinstance(h, str) else h.get("name", "")
            if name == target_role:
                return self._container_name(name)

        zones = topology.get("zones", {})
        if isinstance(zones, dict):
            candidates = zones.get(target_zone, [])
            if isinstance(candidates, list):
                for candidate in candidates:
                    host_name = str(candidate).strip()
                    if host_name:
                        return self._container_name(host_name)

        # Use positional convention: first host for Red, last for Blue
        fallback = hosts[0] if action.mode == "red" else hosts[-1]
        name = fallback if isinstance(fallback, str) else fallback.get("name", fallback.get("hostname", ""))
        logger.warning(
            "No host with role=%s or zone=%s found; using positional fallback: %s",
            target_role, target_zone, name,
        )
        return self._container_name(name)

    def _topology_host_names(self) -> list[str]:
        """Return deduplicated host names from the active snapshot topology."""
        if not self._snapshot or not isinstance(self._snapshot.topology, dict):
            return []
        hosts = self._snapshot.topology.get("hosts", [])
        names: list[str] = []
        for host in hosts:
            if isinstance(host, str):
                candidate = host
            elif isinstance(host, dict):
                candidate = host.get("name") or host.get("hostname") or ""
            else:
                candidate = ""
            name = str(candidate).strip()
            if name and name not in names:
                names.append(name)
        return names

    def _refresh_services_status(self) -> None:
        """Refresh ``state.services_status`` from runtime/container health.

        Availability reward should never rely on an empty status map after reset.
        When health cannot be verified, host status is marked ``"unknown"``.
        """
        host_names = self._topology_host_names()
        if not host_names:
            self._state.services_status = {}
            return

        status_map = {host: "unknown" for host in host_names}

        if self._execution_mode == "docker" and self._docker_available is not False:
            client = self._get_docker()
            if client is not None:
                for host in host_names:
                    container_name = self._container_name(host)
                    try:
                        container = client.containers.get(container_name)
                        status_map[host] = str(getattr(container, "status", "unknown") or "unknown")
                    except Exception:
                        status_map[host] = "down"
                self._state.services_status = status_map
                return

        if self._execution_mode == "subprocess" and self._snapshot and self._snapshot.services:
            checks_by_host: dict[str, list[bool]] = {}
            for svc in self._snapshot.services:
                host = str(getattr(svc, "host", "") or "").strip()
                if not host:
                    continue
                checks_by_host.setdefault(host, []).append(self._probe_readiness(svc.readiness))
            for host, checks in checks_by_host.items():
                status_map[host] = "healthy" if checks and all(checks) else "degraded"

        self._state.services_status = status_map

    # -----------------------------------------------------------------
    # Core API
    # -----------------------------------------------------------------

    def reset(
        self,
        seed: int | None = None,
        episode_id: str | None = None,
        **kwargs: Any,
    ) -> RangeObservation:
        """Reset the environment with a new (or provided) snapshot.

        Args:
            seed: Optional random seed for reproducibility.
            episode_id: Optional episode identifier.
            **kwargs: May include 'snapshot' (SnapshotSpec) or
                      'snapshot_id' (str) to select a specific snapshot.

        Returns:
            Initial RangeObservation with the challenge briefing.
        """
        self._report_episode_result(completed=False)
        self._stop_npcs()
        self._teardown_active_project()

        # Stop services from previous episode (subprocess mode)
        self._stop_services()

        # Select snapshot
        self._snapshot = self._select_snapshot(**kwargs)

        # Reset episode state
        eid = episode_id or str(uuid4())
        tier = self._snapshot.topology.get("tier", 1) if isinstance(
            self._snapshot.topology, dict
        ) else 1
        self._state = RangeState(
            episode_id=eid,
            step_count=0,
            mode="red",
            flags_found=[],
            services_status={},
            tier=tier,
        )
        self._red_history = []
        self._blue_history = []
        self._npc_traffic_log = []
        self._episode_start = time.time()
        self._episode_recorded = False
        try:
            from open_range.server.console import clear_episode, clear_history

            clear_episode()
            clear_history()
        except Exception:
            pass

        # Runtime-backed episodes boot a fresh project per reset. Manual/mock
        # snapshots still use direct artifact application.
        activated = self._activate_runtime_snapshot(self._snapshot, episode_id=eid)

        # Start services BEFORE applying snapshot data so that daemons
        # (MySQL, slapd, etc.) are ready to receive SQL / LDIF payloads.
        self._start_snapshot_services(self._snapshot)

        if not activated:
            self._apply_snapshot(self._snapshot)

        # Initialize zone router from topology (subprocess mode)
        if self._execution_mode == "subprocess":
            from open_range.server.zone_router import ZoneRouter

            topology = self._snapshot.topology if isinstance(self._snapshot.topology, dict) else {}
            self._zone_router = ZoneRouter.from_snapshot(topology)

        # Start NPC traffic for this episode
        self._start_npcs(self._snapshot)

        # Prime service health map for availability reward grounding.
        self._refresh_services_status()

        # Build initial briefing
        task = self._snapshot.task
        if isinstance(task, dict):
            red_briefing = task.get("red_briefing", "")
            blue_briefing = task.get("blue_briefing", "")
        else:
            red_briefing = getattr(task, "red_briefing", "")
            blue_briefing = getattr(task, "blue_briefing", "")

        briefing = (
            f"=== EPISODE {eid} ===\n"
            f"Tier: {self._state.tier}\n\n"
            f"RED BRIEFING:\n{red_briefing}\n\n"
            f"BLUE BRIEFING:\n{blue_briefing}\n\n"
            f"Range ready. Max steps: {self._max_steps}."
        )

        logger.info(
            "Episode %s reset: tier=%d, flags=%d, golden_path_steps=%d",
            eid,
            self._state.tier,
            len(self._snapshot.flags or []),
            len(self._snapshot.golden_path or []),
        )

        self._publish_console_state()
        return RangeObservation(stdout=briefing)

    def step(
        self,
        action: RangeAction,
        timeout_s: float | None = None,
        **kwargs: Any,
    ) -> RangeObservation:
        """Execute an agent action against the range.

        Routes the command to the appropriate container, logs it for
        cross-role reward coupling, computes rewards, and checks
        termination conditions.

        Args:
            action: The agent's action (command + mode).
            timeout_s: Optional per-step timeout override.

        Returns:
            RangeObservation with command output and reward.
        """
        if self._snapshot is None:
            self._snapshot = self._select_snapshot(**kwargs)
            tier = self._snapshot.topology.get("tier", 1) if isinstance(
                self._snapshot.topology, dict
            ) else 1
            self._state = RangeState(
                episode_id=self._state.episode_id or str(uuid4()),
                step_count=0,
                mode=action.mode,
                flags_found=list(self._state.flags_found),
                services_status=dict(self._state.services_status),
                tier=tier,
            )

        self._state.step_count += 1
        self._state.mode = action.mode

        cmd_name = _extract_command_name(action.command)
        if not cmd_name:
            obs = RangeObservation(
                stdout="",
                stderr="Empty command",
                done=self._state.step_count >= self._max_steps,
            )
            self._publish_console_state()
            return obs

        # Handle meta-commands (processed by environment, not forwarded to containers)
        meta_handlers = {
            "submit_flag": self._handle_submit_flag,
            "submit_evidence": self._handle_submit_evidence,
            "submit_finding": self._handle_submit_finding,
            "auth": self._handle_auth,
            "logout": self._handle_logout,
        }

        if cmd_name in meta_handlers:
            obs = meta_handlers[cmd_name](action)
            self._refresh_services_status()
            obs = self._apply_rewards(action, obs)
            self._check_termination(obs)
            self._report_if_done(obs)
            self._publish_console_state()
            return obs

        # Route to container
        target = self._resolve_target(action)
        timeout = timeout_s or self._exec_timeout
        stdout, stderr = self._exec_in_container(
            target,
            action.command,
            timeout_s=timeout,
        )

        # Log action for cross-role reward coupling
        action_record = {
            "step": self._state.step_count,
            "command": action.command,
            "cmd_name": cmd_name,
            "target": target,
            "time": time.time(),
        }

        if action.mode == "red":
            self._red_history.append(action_record)
        else:
            self._blue_history.append(action_record)
        try:
            from open_range.server.console import record_action

            record_action({"mode": action.mode, **action_record})
        except Exception:
            pass

        # Check for milestone completion (#17)
        milestone = self._check_milestone(stdout)
        if milestone and milestone not in self._state.milestones_completed:
            self._state.milestones_completed.append(milestone)

        # Check for pivot opportunities (#26)
        self._check_pivot(action, stdout)

        # Refresh NPC traffic log for reward computation
        self._refresh_npc_traffic_log()
        self._refresh_services_status()

        # Build observation
        obs = RangeObservation(
            stdout=stdout,
            stderr=stderr,
            flags_captured=[],
            alerts=self._get_pending_alerts() if action.mode == "blue" else [],
        )

        # Compute rewards and check termination
        obs = self._apply_rewards(action, obs)
        self._check_termination(obs)
        self._report_if_done(obs)

        self._publish_console_state()
        return obs

    @property
    def state(self) -> RangeState:
        """Return the current episode state."""
        return self._state

    # -----------------------------------------------------------------
    # Reward integration
    # -----------------------------------------------------------------

    def _get_reward_instances(self) -> tuple[Any, Any]:
        """Lazy-load reward calculators."""
        if self._red_reward is None:
            from open_range.server.rewards import CompositeRedReward, CompositeBlueReward

            self._red_reward = CompositeRedReward()
            self._blue_reward = CompositeBlueReward()
        return self._red_reward, self._blue_reward

    def _apply_rewards(
        self, action: RangeAction, obs: RangeObservation
    ) -> RangeObservation:
        """Compute and attach reward to the observation."""
        if self._snapshot is None:
            return obs

        red_reward, blue_reward = self._get_reward_instances()

        reward_ctx = {
            "red_history": self._red_history,
            "blue_history": self._blue_history,
            "npc_traffic_log": self._npc_traffic_log,
            "snapshot": self._snapshot,
            "state": self._state,
        }

        try:
            if action.mode == "red":
                obs.reward = red_reward.compute(
                    action, obs, self._state, self._snapshot, reward_ctx
                )
            else:
                obs.reward = blue_reward.compute(
                    action, obs, self._state, self._snapshot, reward_ctx
                )
        except Exception as exc:
            logger.error("Reward computation failed: %s", exc, exc_info=True)
            obs.reward = 0.0

        return obs

    # -----------------------------------------------------------------
    # Termination
    # -----------------------------------------------------------------

    def _check_termination(self, obs: RangeObservation) -> None:
        """Set done=True if any termination condition is met."""
        if obs.done:
            return  # Already terminated (e.g. all flags captured)

        # Max steps
        if self._state.step_count >= self._max_steps:
            obs.done = True
            return

        # All flags captured
        if self._snapshot and self._snapshot.flags:
            valid_flags = {f.value for f in self._snapshot.flags}
            if valid_flags and set(self._state.flags_found) >= valid_flags:
                obs.done = True
                return

    def _report_if_done(self, obs: RangeObservation) -> None:
        """Report a completed episode to the shared runtime once."""
        if obs.done:
            self._report_episode_result(completed=True)

    def _report_episode_result(self, completed: bool) -> None:
        """Record the current episode outcome with the shared runtime."""
        if self._episode_recorded or self._runtime is None or self._snapshot is None:
            return
        if self._state.episode_id is None:
            return

        self._runtime.record_episode_result(
            snapshot_id=self._snapshot_id,
            snapshot=self._snapshot,
            state=self._state,
            red_history=self.red_history,
            blue_history=self.blue_history,
            completed=completed,
        )
        self._episode_recorded = True

    # -----------------------------------------------------------------
    # Alert system
    # -----------------------------------------------------------------

    def _query_siem_alerts(self) -> list[str]:
        """Query the SIEM host for real alert log entries.

        Searches consolidated SIEM logs for error, warning, and attack
        indicators. Returns up to 20 recent matching lines.
        """
        siem_target = self._resolve_target(RangeAction(command="", mode="blue"))
        stdout, _ = self._exec_in_container(
            siem_target,
            "grep -i 'error\\|warning\\|suspicious\\|denied\\|attack\\|scan' "
            "/var/log/siem/consolidated/*.log 2>/dev/null | tail -20",
            timeout_s=5.0,
        )
        if stdout and stdout.strip():
            return [line for line in stdout.strip().splitlines() if line.strip()]
        return []

    def _get_pending_alerts(self) -> list[str]:
        """Return alerts from Red's recent actions for Blue to observe.

        In production (docker or subprocess mode with real infrastructure),
        queries the SIEM container for actual log-based alerts. Falls back
        to synthetic alerts derived from Red action history when SIEM queries
        return nothing or in unit-test mock mode (capped to recent 20 lines).
        """
        # Try real SIEM query in non-mock modes
        if self._docker_available is not False or self._execution_mode == "subprocess":
            siem_alerts = self._query_siem_alerts()
            if siem_alerts:
                return siem_alerts

        # Fallback: synthesize alerts from recent Red actions so Blue still
        # receives actionable signal in mock/degraded SIEM paths.
        synthetic: list[str] = []
        for record in self._red_history:
            if record.get("type") in ("hallucinated_flag", "evidence"):
                continue
            command = str(record.get("command", "")).strip()
            if not command:
                continue
            step = record.get("step", "?")
            cmd_name = str(record.get("cmd_name", "")).strip() or _extract_command_name(command)
            target = str(record.get("target", "")).strip()
            if target:
                synthetic.append(f"[synthetic] step={step} cmd={cmd_name} target={target} :: {command}")
            else:
                synthetic.append(f"[synthetic] step={step} cmd={cmd_name} :: {command}")
        return synthetic[-20:]

    # -----------------------------------------------------------------
    # Introspection (for reward computation and debugging)
    # -----------------------------------------------------------------

    @property
    def snapshot(self) -> SnapshotSpec | None:
        """The current episode's snapshot spec (truth data)."""
        return self._snapshot

    @property
    def red_history(self) -> list[dict[str, Any]]:
        """Red's action log for this episode."""
        return list(self._red_history)

    @property
    def blue_history(self) -> list[dict[str, Any]]:
        """Blue's action log for this episode."""
        return list(self._blue_history)

    @property
    def npc_traffic_log(self) -> list[dict[str, Any]]:
        """NPC traffic log for this episode (labeled for FP scoring)."""
        return list(self._npc_traffic_log)

    def close(self) -> None:
        """Release resources (Docker client, NPC manager, episode state)."""
        self._report_episode_result(completed=False)
        self._stop_npcs()
        self._stop_services()
        self._teardown_active_project()
        if self._docker_client is not None:
            try:
                self._docker_client.close()
            except Exception:
                pass
            self._docker_client = None
