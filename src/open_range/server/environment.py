"""RangeEnvironment -- OpenEnv Environment for the OpenRange cyber gymnasium.

If openenv is installed, inherits from Environment[RangeAction, RangeObservation, RangeState].
Otherwise works standalone with the same API surface.

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
import time
from typing import Any
from uuid import uuid4

from open_range.protocols import SnapshotSpec, TaskSpec

from open_range.server.models import RangeAction, RangeObservation, RangeState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try to inherit from OpenEnv's Environment base class
# ---------------------------------------------------------------------------

try:
    from openenv.core.env_server.interfaces import Environment

    _BASE = Environment  # type: ignore[assignment]
    _HAS_OPENENV = True
except ImportError:
    _BASE = object  # type: ignore[assignment,misc]
    _HAS_OPENENV = False

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


class RangeEnvironment(_BASE):  # type: ignore[misc]
    """OpenEnv Environment subclass for the cybersecurity range.

    Manages episode lifecycle, command routing, action tracking, and
    reward computation for Red/Blue tandem training.
    """

    SUPPORTS_CONCURRENT_SESSIONS = False

    def __init__(
        self,
        max_steps: int = DEFAULT_MAX_STEPS,
        exec_timeout: float = EXEC_TIMEOUT,
        docker_available: bool | None = None,
    ) -> None:
        if _HAS_OPENENV:
            super().__init__()
        self._state = RangeState()
        self._snapshot: SnapshotSpec | None = None
        self._red_history: list[dict[str, Any]] = []
        self._blue_history: list[dict[str, Any]] = []
        self._npc_traffic_log: list[dict[str, Any]] = []
        self._max_steps = max_steps
        self._exec_timeout = exec_timeout
        self._episode_start: float = 0.0

        # Reward instances -- imported lazily to avoid circular deps
        self._red_reward: Any = None
        self._blue_reward: Any = None

        # Docker client -- resolved lazily
        self._docker_client: Any = None
        self._docker_available = docker_available

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
        """Resolve logical host name to Docker container name."""
        if self._snapshot and self._snapshot.compose:
            services = self._snapshot.compose.get("services", {})
            if host in services:
                project = self._snapshot.compose.get(
                    "x-project-name", "openrange"
                )
                return f"{project}-{host}-1"
        return host

    def _exec_in_container(
        self, container_name: str, command: str
    ) -> tuple[str, str]:
        """Execute a command inside a Docker container.

        Returns (stdout, stderr). Falls back to a stub when Docker is
        unavailable (e.g. during unit tests).
        """
        client = self._get_docker()
        if client is None:
            return (
                f"[mock] executed on {container_name}: {command}",
                "",
            )
        try:
            container = client.containers.get(container_name)
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
            return kwargs["snapshot"]

        # In production, a SnapshotStore would be consulted here.
        # For now, return a minimal placeholder.
        return SnapshotSpec(
            topology={"hosts": []},
            flags=[],
            golden_path=[],
            task={
                "red_briefing": (
                    "Target network detected. Begin reconnaissance and "
                    "identify vulnerabilities. Capture all flags."
                ),
                "blue_briefing": (
                    "Monitor SIEM for suspicious activity. Investigate "
                    "alerts, patch vulnerabilities, and report findings."
                ),
            },
        )

    # -----------------------------------------------------------------
    # Special command handling
    # -----------------------------------------------------------------

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

        valid_flags = {f.value for f in self._snapshot.flags}
        already_found = set(self._state.flags_found)

        if submitted in valid_flags and submitted not in already_found:
            self._state.flags_found.append(submitted)
            # Check if all flags captured
            all_captured = set(self._state.flags_found) == valid_flags
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
        self._blue_history.append({
            "step": self._state.step_count,
            "type": "finding",
            "content": finding,
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
        parts = action.command.strip().split()
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

        For Red: commands run on the attacker container (or specified target).
        For Blue: commands run on the SIEM container.
        """
        if action.mode == "red":
            return self._container_name("attacker")
        else:
            return self._container_name("siem")

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
            len(self._snapshot.flags),
            len(self._snapshot.golden_path),
        )

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
        self._state.step_count += 1
        self._state.mode = action.mode

        cmd_name = _extract_command_name(action.command)
        if not cmd_name:
            return RangeObservation(
                stdout="",
                stderr="Empty command",
                done=self._state.step_count >= self._max_steps,
            )

        # Handle meta-commands (processed by environment, not forwarded to containers)
        if cmd_name == "submit_flag":
            obs = self._handle_submit_flag(action)
            obs = self._apply_rewards(action, obs)
            self._check_termination(obs)
            return obs

        if cmd_name == "submit_evidence":
            obs = self._handle_submit_evidence(action)
            obs = self._apply_rewards(action, obs)
            self._check_termination(obs)
            return obs

        if cmd_name == "submit_finding":
            obs = self._handle_submit_finding(action)
            obs = self._apply_rewards(action, obs)
            self._check_termination(obs)
            return obs

        if cmd_name == "auth":
            obs = self._handle_auth(action)
            obs = self._apply_rewards(action, obs)
            self._check_termination(obs)
            return obs

        if cmd_name == "logout":
            obs = self._handle_logout(action)
            obs = self._apply_rewards(action, obs)
            self._check_termination(obs)
            return obs

        # Route to container
        target = self._resolve_target(action)
        timeout = timeout_s or self._exec_timeout
        stdout, stderr = self._exec_in_container(target, action.command)

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

        # Check for milestone completion (#17)
        milestone = self._check_milestone(stdout)
        if milestone and milestone not in self._state.milestones_completed:
            self._state.milestones_completed.append(milestone)

        # Check for pivot opportunities (#26)
        self._check_pivot(action, stdout)

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
            logger.warning("Reward computation failed: %s", exc)
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

    # -----------------------------------------------------------------
    # Alert system
    # -----------------------------------------------------------------

    def _get_pending_alerts(self) -> list[str]:
        """Return alerts from Red's recent actions for Blue to observe.

        In a full deployment, these would come from the SIEM container.
        In mock mode, we generate synthetic alerts from Red's action history.
        """
        alerts: list[str] = []
        for record in self._red_history:
            cmd = record.get("cmd_name", "")
            if cmd in ("nmap", "nikto", "hydra", "sqlmap"):
                alerts.append(
                    f"[IDS] Suspicious activity detected: {cmd} scan "
                    f"at step {record['step']}"
                )
        return alerts

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
