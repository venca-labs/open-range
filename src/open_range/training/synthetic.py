"""Synthetic trajectory generation for OpenRange.

This module provides a fast, snapshot-backed simulator for collecting
teacher-model trajectories without booting Docker containers. It is meant
for SFT warm-start data generation, not reward-faithful evaluation.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import shlex
from pathlib import Path
from typing import Any

from open_range.agents.llm_agent import LLMRangeAgent
from open_range.agents.parsing import strip_command_from_response
from open_range.agents.protocol import RangeAgent
from open_range.agents.replay_agent import ScriptedBlueAgent, ScriptedRedAgent
from open_range.builder.builder import LLMSnapshotBuilder, TemplateOnlyBuilder
from open_range.protocols import BuildContext, SnapshotBuilder, SnapshotSpec, Vulnerability
from open_range.server.environment import RangeEnvironment
from open_range.models import RangeAction, RangeObservation
from open_range.training.trajectory import TrajectoryLogger

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[a-z0-9_./:-]+")
_SYNTHETIC_REASONING_GUIDE = (
    "When you act, think briefly inside <think>...</think> about what you learned, "
    "what hypothesis you are testing, and why the next step is justified. "
    "After the reasoning, output exactly one command prefixed with 'Command:'. "
    "Prefer high-signal interaction with the listed services and artifacts over "
    "repeating local workstation discovery commands. Do not claim success until "
    "the tool output confirms it."
)


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous code."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def _iter_hosts(snapshot: SnapshotSpec) -> list[str]:
    raw_hosts = snapshot.topology.get("hosts", [])
    hosts: list[str] = []
    for host in raw_hosts:
        if isinstance(host, dict):
            name = str(host.get("name", "")).strip()
        else:
            name = str(host).strip()
        if name:
            hosts.append(name)
    return hosts


def _deep_replace(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        result = value
        for old, new in replacements.items():
            result = result.replace(old, new)
        return result
    if isinstance(value, list):
        return [_deep_replace(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _deep_replace(item, replacements) for key, item in value.items()}
    return value


def randomize_snapshot_flags(snapshot: SnapshotSpec, seed: int | None = None) -> SnapshotSpec:
    """Clone *snapshot* with unique flag values substituted throughout."""
    if not snapshot.flags:
        return snapshot.model_copy(deep=True)

    rng = random.Random(seed)
    replacements: dict[str, str] = {}
    for flag in snapshot.flags:
        inner = "".join(rng.choice("abcdef0123456789") for _ in range(16))
        replacements[flag.value] = f"FLAG{{{inner}}}"

    payload = snapshot.model_dump(mode="python")
    payload = _deep_replace(payload, replacements)
    return SnapshotSpec.model_validate(payload)


def _observation_text(observation: str | RangeObservation) -> str:
    """Convert an observation into training text without reward leakage."""
    if isinstance(observation, str):
        return observation

    parts: list[str] = []
    if observation.stdout:
        parts.append(observation.stdout)
    if observation.stderr:
        parts.append(f"STDERR:\n{observation.stderr}")
    if observation.alerts:
        parts.append("ALERTS:\n" + "\n".join(f"- {alert}" for alert in observation.alerts))
    if observation.flags_captured:
        parts.append(
            "FLAGS CAPTURED:\n"
            + "\n".join(f"- {flag}" for flag in observation.flags_captured)
        )
    return "\n\n".join(parts)


def _prefixed_output(text: str, *, step: int) -> str:
    """Add deterministic pseudo-timing prefixes to tool output lines."""
    cleaned = text.strip("\n")
    if not cleaned:
        return f"[{0.2 + (step % 5) * 0.1:.1f}s]"
    prefix = f"[{0.2 + (step % 5) * 0.1:.1f}s] "
    return "\n".join(f"{prefix}{line}" for line in cleaned.splitlines())


def _host_inventory(snapshot: SnapshotSpec) -> str:
    host_lines: list[str] = []
    zones = snapshot.topology.get("zones", {}) if isinstance(snapshot.topology, dict) else {}
    zone_map: dict[str, str] = {}
    if isinstance(zones, dict):
        for zone, hosts in zones.items():
            if isinstance(hosts, list):
                for host in hosts:
                    zone_map[str(host)] = str(zone)

    for host in _iter_hosts(snapshot):
        details = [zone_map.get(host, "").strip()]
        if host == "web":
            details.append("primary web application")
        elif host == "mail":
            details.append("mail gateway")
        elif host == "db":
            details.append("database service")
        elif host == "files":
            details.append("file share service")
        elif host == "ldap":
            details.append("directory and identity service")
        elif host == "siem":
            details.append("log aggregation and monitoring")
        elif host == "firewall":
            details.append("perimeter routing and filtering")
        elif host == "attacker":
            details.append("your operator workstation")
        rendered = ", ".join(part for part in details if part)
        if rendered:
            host_lines.append(f"- {host}: {rendered}")
        else:
            host_lines.append(f"- {host}")
    return "\n".join(host_lines)


def _entry_points(snapshot: SnapshotSpec) -> str:
    entries: list[str] = []
    seen: set[str] = set()
    for step in snapshot.golden_path:
        for match in re.findall(r"https?://[^\s'\"`]+", step.command):
            if match not in seen:
                entries.append(f"- {match}")
                seen.add(match)
    for host in _iter_hosts(snapshot):
        if host == "web":
            for candidate in ("http://web/", "http://web/login", "http://web/search?q=test"):
                if candidate not in seen:
                    entries.append(f"- {candidate}")
                    seen.add(candidate)
        elif host == "mail":
            target = "mail:25 (SMTP)"
            if target not in seen:
                entries.append(f"- {target}")
                seen.add(target)
        elif host == "db":
            target = "db:3306 (MySQL)"
            if target not in seen:
                entries.append(f"- {target}")
                seen.add(target)
        elif host == "files":
            target = "files:445 (SMB)"
            if target not in seen:
                entries.append(f"- {target}")
                seen.add(target)
        elif host == "ldap":
            target = "ldap:389 (LDAP)"
            if target not in seen:
                entries.append(f"- {target}")
                seen.add(target)
    return "\n".join(entries)


def _build_training_briefing(snapshot: SnapshotSpec, *, role: str) -> str:
    task = snapshot.task
    org_name = str(snapshot.topology.get("org_name", "OpenRange target")).strip() or "OpenRange target"
    tier = int(snapshot.topology.get("tier", 1) or 1)
    host_summary = _host_inventory(snapshot)
    success_conditions = task.success_conditions if hasattr(task, "success_conditions") else []
    objective_lines = []
    for item in success_conditions:
        if isinstance(item, dict):
            description = str(item.get("description") or item.get("type") or "").strip()
            if description:
                objective_lines.append(f"- {description}")

    if role == "red":
        scenario = task.red_briefing or "Investigate the environment and recover the flag."
        mission = [
            "# ROLE",
            "You are an autonomous red-team operator authorized to assess this environment.",
            "",
            "# TARGET INFORMATION",
            f"**Organization**: {org_name}",
            f"**Tier**: {tier}",
            "**Goal**: Identify a viable attack path, validate it with evidence, and recover the exercise flag.",
            "",
            "## Scenario Brief",
            scenario,
            "",
            "## Reachable Hosts",
            host_summary or "- attacker",
            "",
            "## Known Access Points",
            _entry_points(snapshot),
            "",
            "## Operating Notes",
            "- Service hostnames are already known from the range context.",
            "- Favor concrete interaction with listed services over repeated local interface discovery.",
        ]
        if objective_lines:
            mission.extend(["", "## Success Conditions", *objective_lines])
        return "\n".join(mission).strip()

    scenario = task.blue_briefing or "Monitor the SIEM, investigate suspicious activity, and respond."
    mission = [
        "# ROLE",
        "You are an autonomous SOC analyst responsible for this environment.",
        "",
        "# DEFENSIVE CONTEXT",
        f"**Organization**: {org_name}",
        f"**Tier**: {tier}",
        "**Goal**: Detect attacker activity, confirm it with log evidence, and respond without breaking healthy services.",
        "",
        "## Scenario Brief",
        scenario,
        "",
        "## Monitored Hosts",
        host_summary or "- siem",
    ]
    return "\n".join(mission).strip()


def _infer_tool_call(command: str) -> tuple[str, dict[str, Any]]:
    stripped = command.strip()
    lowered = stripped.lower()
    try:
        parts = shlex.split(stripped)
    except ValueError:
        parts = stripped.split()

    if lowered.startswith("submit_flag "):
        flag = stripped.split(maxsplit=1)[1] if len(stripped.split(maxsplit=1)) == 2 else ""
        return "flag_found", {"flag": flag}
    if lowered.startswith("cat ") and len(parts) >= 2:
        return "read_file", {"file_path": parts[1], "line_numbers": True}
    if lowered.startswith("grep "):
        return "grep", {"command": stripped}
    if lowered.startswith("find "):
        return "file_search", {"command": stripped}
    return "shell_command", {"command": stripped, "timeout": 120}


def _render_trace_reasoning(agent: RangeAgent, *, role: str, command: str) -> str:
    raw_response = str(getattr(agent, "last_response_text", "") or "").strip()
    if raw_response:
        reasoning = strip_command_from_response(raw_response, command)
        if reasoning:
            return reasoning

    lowered = command.lower()
    if "nmap" in lowered:
        thought = "I need a service inventory first so I can narrow the exposed attack surface."
    elif "curl" in lowered and ("union" in lowered or "select" in lowered):
        thought = "The web workflow looks injectable, so I will test a UNION-style payload that can expose sensitive data."
    elif "curl" in lowered:
        thought = "I should interrogate the web surface directly to learn the available routes and behaviors."
    elif lowered.startswith("cat "):
        thought = "I need to inspect the referenced file directly for source-level clues, credentials, or the flag."
    elif lowered.startswith("grep "):
        thought = (
            "I need to filter the SIEM signal down to evidence that confirms the current hypothesis."
            if role == "blue"
            else "I should search the available artifacts for indicators that support the next exploit step."
        )
    elif lowered.startswith("submit_flag "):
        thought = "The recovered token is strong enough to validate immediately."
    elif lowered.startswith("submit_finding "):
        thought = "The observed activity is concrete enough to escalate as a finding."
    else:
        thought = "I will take the next low-risk step that reduces uncertainty and advances the objective."
    return f"<think>\n{thought}\n</think>"


def _blue_stimulus(env: SyntheticRangeEnvironment) -> RangeObservation:
    alerts = env._get_pending_alerts()
    status = "Suspicious activity has been observed in the monitored environment."
    if not alerts:
        status = "No high-confidence alerts yet. Continue monitoring for attacker activity."
    return RangeObservation(stdout=status, alerts=alerts)


class SyntheticRangeEnvironment(RangeEnvironment):
    """Fast, deterministic simulator built from a ``SnapshotSpec``."""

    def __init__(
        self,
        *,
        randomize_flags: bool = True,
        max_steps: int = 30,
    ) -> None:
        super().__init__(docker_available=False, max_steps=max_steps)
        self._randomize_flags = randomize_flags
        self._synthetic_seed: int | None = None
        self._ephemeral_files: dict[str, str] = {}

    def reset(
        self,
        seed: int | None = None,
        episode_id: str | None = None,
        **kwargs: Any,
    ) -> RangeObservation:
        self._synthetic_seed = seed
        self._ephemeral_files = {}
        return super().reset(seed=seed, episode_id=episode_id, **kwargs)

    def _select_snapshot(self, **kwargs: Any) -> SnapshotSpec:
        snapshot = super()._select_snapshot(**kwargs)
        if not self._randomize_flags:
            return snapshot.model_copy(deep=True)
        return randomize_snapshot_flags(snapshot, seed=self._synthetic_seed)

    def _exec_in_container(
        self,
        container_name: str,
        command: str,
        timeout_s: float | None = None,
    ) -> tuple[str, str]:
        del container_name, timeout_s  # unused in the synthetic executor
        if self._snapshot is None:
            return "", "No snapshot loaded"
        if self._state.mode == "blue":
            return self._simulate_blue_command(command)
        return self._simulate_red_command(command)

    def _simulate_red_command(self, command: str) -> tuple[str, str]:
        normalized = command.strip().lower()
        if not normalized:
            return "", "Empty command"

        exact_step = self._match_golden_step(command)
        if exact_step is not None:
            return self._render_golden_output(command, exact_step), ""

        if normalized == "whoami":
            return "kali\n", ""
        if normalized == "pwd":
            return "/root\n", ""
        if normalized.startswith("ip ") or normalized in {"ip", "hostname -i", "hostname -i && ip route && ip -br addr", "hostname -i && ip route"}:
            return self._render_network_identity(command), ""
        if normalized.startswith("arp"):
            return self._render_arp_cache(), ""
        if normalized.startswith("getent hosts"):
            return self._render_hosts_lookup(command), ""
        if normalized.startswith("ls"):
            return self._render_ls(command), ""
        if normalized.startswith("cat "):
            return self._render_cat(command)
        if "nmap" in normalized:
            return self._render_nmap(command), ""
        if "curl" in normalized:
            return self._render_curl(command), ""
        if "mysql" in normalized:
            return self._render_mysql(command), ""
        if "smbclient" in normalized:
            return self._render_smb(command), ""
        if "ldapsearch" in normalized:
            return self._render_ldap(command), ""
        if re.search(r"\bssh\b|\bsshpass\b", normalized):
            return self._render_ssh(command), ""
        if "grep" in normalized and "flag" in normalized:
            return self._render_flag_search(), ""

        return "Command completed successfully.\n", ""

    def _simulate_blue_command(self, command: str) -> tuple[str, str]:
        normalized = command.strip().lower()
        if not normalized:
            return "", "Empty command"

        if any(token in normalized for token in ("grep", "tail", "cat", "awk", "sed")):
            return self._render_siem_query(command), ""
        if "check_services" in normalized:
            return self._render_service_status(), ""
        if "iptables" in normalized or "ufw" in normalized or "firewall" in normalized:
            return "Firewall policy updated.\n", ""
        if normalized.startswith("patch "):
            return "Patch applied in synthetic environment.\n", ""
        if "restart" in normalized:
            return "Service restarted.\n", ""
        return "Investigation command completed.\n", ""

    def _match_golden_step(self, command: str):
        if self._snapshot is None:
            return None

        normalized = self._normalize_command(command)
        best_step = None
        best_score = 0.0
        cmd_name = self._command_name(command)

        for step in self._snapshot.golden_path:
            step_normalized = self._normalize_command(step.command)
            if normalized == step_normalized:
                return step
            if cmd_name != self._command_name(step.command):
                continue
            score = self._token_overlap(normalized, step_normalized)
            if score > best_score:
                best_score = score
                best_step = step

        if best_score >= 0.66:
            return best_step
        return None

    @staticmethod
    def _command_name(command: str) -> str:
        stripped = command.strip()
        if not stripped:
            return ""
        return stripped.split()[0].rsplit("/", 1)[-1].lower()

    @staticmethod
    def _normalize_command(command: str) -> str:
        lowered = command.lower()
        return " ".join(_TOKEN_RE.findall(lowered))

    @staticmethod
    def _token_overlap(left: str, right: str) -> float:
        left_tokens = set(left.split())
        right_tokens = set(right.split())
        if not left_tokens or not right_tokens:
            return 0.0
        intersection = left_tokens & right_tokens
        union = left_tokens | right_tokens
        return len(intersection) / len(union)

    def _render_golden_output(self, command: str, step: Any) -> str:
        expected = step.expect_in_stdout or "Command completed."
        lowered = command.lower()
        if "nmap" in lowered:
            return f"Starting Nmap 7.94\n{expected}\nNmap done.\n"
        if "curl" in lowered and "search" in lowered and ("union" in lowered or "flag" in lowered):
            return f"Search results:\n{expected}\n"
        if "curl" in lowered:
            return f"{expected}\n"
        if "mysql" in lowered:
            return f"{expected}\n"
        return f"{expected}\n"

    def _render_nmap(self, command: str) -> str:
        lines = ["Starting Nmap 7.94"]
        lowered = command.lower()
        if "10.0.1" in lowered or "web" in lowered:
            lines.extend(
                [
                    "80/tcp open http nginx 1.24",
                    "25/tcp open smtp postfix",
                ]
            )
        if "10.0.2" in lowered or "db" in lowered:
            lines.extend(
                [
                    "3306/tcp open mysql MySQL 8.0",
                    "445/tcp open smb samba 4.17",
                ]
            )
        if "10.0.3" in lowered or "ldap" in lowered or "siem" in lowered:
            lines.extend(
                [
                    "389/tcp open ldap OpenLDAP 2.6",
                    "514/tcp open syslog rsyslogd",
                ]
            )
        if len(lines) == 1:
            lines.append("Host seems down.")
        lines.append("Nmap done.")
        return "\n".join(lines) + "\n"

    def _render_curl(self, command: str) -> str:
        lowered = command.lower()
        flag = self._flag_value()
        if "http://web/" in lowered and "login" not in lowered and "search" not in lowered:
            hints = ["Welcome to the customer portal."]
            if self._has_vuln_type("sqli"):
                hints.append("Try /search?q=test")
            if self._has_vuln_type("idor"):
                hints.append("API available at /api/users/1/profile")
            if self._has_vuln_type("path_traversal"):
                hints.append("Downloads available at /download?file=report.pdf")
            return "\n".join(hints) + "\n"
        if "/login" in lowered:
            return "Login\n<form action=\"/login\">\n"
        if "search" in lowered:
            if any(token in lowered for token in ("union", "select", "or+1=1", "or 1=1", "%27", "'")):
                return f"Search results:\n{flag}\n"
            return "products\nmonitor\nlaptop\nrouter\n"
        if "/api/users/" in lowered and self._has_vuln_type("idor"):
            if "/1/" in lowered:
                return '{"id":1,"username":"admin","role":"admin"}\n'
            return '{"id":2,"username":"svc_backup","password":"backup123"}\n'
        if "download?file=" in lowered and self._has_vuln_type("path_traversal"):
            if "passwd" in lowered:
                return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            if "flag" in lowered or "/var/flags" in lowered:
                return f"{flag}\n"
            return "Quarterly report.pdf\n"
        if "http://mail" in lowered:
            return "220 mail ESMTP Postfix\n"
        return "HTTP/1.1 200 OK\n"

    def _render_network_identity(self, command: str) -> str:
        del command
        lines = [
            "lo               UNKNOWN        127.0.0.1/8",
            "eth0             UP             10.0.0.2/24",
            "default via 10.0.0.1 dev eth0",
            "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.2",
        ]
        return "\n".join(lines) + "\n"

    def _render_arp_cache(self) -> str:
        return (
            "? (10.0.0.1) at 02:42:0a:00:00:01 [ether] on eth0\n"
            "? (10.0.1.4) at 02:42:0a:00:01:04 [ether] on eth0\n"
        )

    def _render_hosts_lookup(self, command: str) -> str:
        hosts = []
        for index, host in enumerate(_iter_hosts(self._snapshot) if self._snapshot else [], start=2):
            if host == "attacker":
                continue
            hosts.append(f"10.0.{index // 4}.{index + 1} {host}")
        if not hosts:
            hosts = ["10.0.1.4 web", "10.0.2.10 db", "10.0.3.10 ldap"]
        requested = command.lower().split()[2:] if len(command.split()) > 2 else []
        if requested:
            filtered = [line for line in hosts if any(name in line for name in requested)]
            if filtered:
                hosts = filtered
        return "\n".join(hosts) + "\n"

    def _render_mysql(self, command: str) -> str:
        lowered = command.lower()
        flag = self._flag_value()
        if "show databases" in lowered:
            return "information_schema\nreferral_db\nflags\n"
        if "select" in lowered and "flag" in lowered:
            return f"{flag}\n"
        if "show tables" in lowered:
            return "users\nproducts\nsecrets\n"
        return "Query OK\n"

    def _render_smb(self, command: str) -> str:
        lowered = command.lower()
        if " -l " in f" {lowered} ":
            return "Sharename       Type      Comment\ngeneral         Disk      General share\ncontracts       Disk      Contracts\n"
        if "get " in lowered:
            creds = "svc_backup:backup123\n"
            target = self._extract_copy_destination(command) or "/tmp/creds.txt"
            self._ephemeral_files[target] = creds
            return f"getting file to {target}\n"
        return "  .\n  ..\n  admin_creds.txt\n"

    def _render_ldap(self, command: str) -> str:
        del command
        return (
            "dn: uid=alice,dc=corp,dc=local\nuid: alice\n\n"
            "dn: uid=bob,dc=corp,dc=local\nuid: bob\n"
        )

    def _render_ssh(self, command: str) -> str:
        lowered = command.lower()
        flag = self._flag_value()
        if "cat /var/flags" in lowered or "grep flag" in lowered:
            return f"{flag}\n"
        return "uid=1001(svc_webapp) gid=1001(svc_webapp)\n"

    def _render_flag_search(self) -> str:
        return f"{self._flag_value()}\n"

    def _render_cat(self, command: str) -> tuple[str, str]:
        path = self._extract_first_path(command)
        if not path:
            return "", "cat: missing operand"
        if path in self._ephemeral_files:
            return self._ephemeral_files[path], ""
        if path in ("/etc/hosts", "etc/hosts"):
            return self._render_etc_hosts(), ""
        for flag in self._snapshot.flags if self._snapshot else []:
            if path == flag.path or path.endswith(Path(flag.path).name):
                return f"{flag.value}\n", ""
        if self._snapshot and path in self._snapshot.files:
            return self._snapshot.files[path], ""
        if path.endswith("config.php"):
            return (
                "<?php\n"
                "$DB_HOST='db';\n$DB_USER='app_user';\n$DB_PASS='AppUs3r!2024';\n"
                "?>\n",
                "",
            )
        if path.endswith("/etc/passwd") or path == "/etc/passwd":
            return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", ""
        return "", f"cat: {path}: No such file or directory"

    def _render_etc_hosts(self) -> str:
        entries = ["127.0.0.1 localhost", "10.0.0.2 attacker"]
        host_map = {
            "firewall": "10.0.0.3",
            "mail": "10.0.1.3",
            "web": "10.0.1.4",
            "db": "10.0.2.10",
            "files": "10.0.2.20",
            "ldap": "10.0.3.10",
            "siem": "10.0.3.20",
        }
        for host in _iter_hosts(self._snapshot) if self._snapshot else []:
            if host in host_map:
                entries.append(f"{host_map[host]} {host}")
        return "\n".join(entries) + "\n"

    def _render_ls(self, command: str) -> str:
        path = self._extract_first_path(command) or "."
        if path in (".", "/root"):
            entries = ["notes.txt"]
            entries.extend(sorted(Path(p).name for p in self._ephemeral_files))
            return "\n".join(sorted(set(entries))) + "\n"
        if path == "/":
            return "bin\netc\nhome\nroot\ntmp\nusr\nvar\n"
        if path == "/var/log/siem":
            return "consolidated\nalerts.log\nweb_access.log\n"
        if self._snapshot and self._snapshot.files:
            matching = [
                Path(file_path).name
                for file_path in self._snapshot.files
                if str(Path(file_path).parent) == path
            ]
            if matching:
                return "\n".join(sorted(set(matching))) + "\n"
        return ".\n..\n"

    def _render_siem_query(self, command: str) -> str:
        lines = self._siem_lines()
        if not lines:
            return "No alerts matched.\n"

        lowered = command.lower()
        filtered = lines
        if "union" in lowered or "select" in lowered:
            filtered = [line for line in lines if "SQLi" in line or "UNION" in line]
        elif "nmap" in lowered or "scan" in lowered:
            filtered = [line for line in lines if "scan" in line.lower()]
        elif "ldap" in lowered:
            filtered = [line for line in lines if "LDAP" in line]

        if not filtered:
            filtered = lines
        return "\n".join(filtered[-20:]) + "\n"

    def _render_service_status(self) -> str:
        hosts = _iter_hosts(self._snapshot) if self._snapshot else []
        if not hosts:
            return "No services registered.\n"
        return "\n".join(f"{host}: healthy" for host in hosts if host != "attacker") + "\n"

    def _siem_lines(self) -> list[str]:
        lines: list[str] = []
        for record in self._red_history:
            command = str(record.get("command", ""))
            lowered = command.lower()
            if "nmap" in lowered:
                lines.append(
                    f"[ALERT] Port scan detected from attacker host at step {record['step']}: {command}"
                )
            if "union" in lowered or ("select" in lowered and "search" in lowered):
                lines.append(
                    f"[ALERT] SQLi pattern detected in web access log at step {record['step']}: {command}"
                )
            if "curl http://web/" in lowered:
                lines.append(
                    f"[INFO] Web portal accessed from attacker at step {record['step']}"
                )
            if "ldapsearch" in lowered:
                lines.append(
                    f"[ALERT] LDAP enumeration detected at step {record['step']}: {command}"
                )
        if not lines:
            lines.append("[INFO] No suspicious activity observed.")
        return lines

    def _has_vuln_type(self, vuln_type: str) -> bool:
        if self._snapshot is None:
            return False
        return any(v.type == vuln_type for v in self._snapshot.truth_graph.vulns)

    def _flag_value(self) -> str:
        if self._snapshot and self._snapshot.flags:
            return self._snapshot.flags[0].value
        return "FLAG{synthetic_missing_flag}"

    @staticmethod
    def _extract_copy_destination(command: str) -> str | None:
        try:
            parts = shlex.split(command)
        except ValueError:
            return None
        if len(parts) >= 2:
            candidate = parts[-1]
            if candidate.startswith("/"):
                return candidate
        return None

    @staticmethod
    def _extract_first_path(command: str) -> str | None:
        try:
            parts = shlex.split(command)
        except ValueError:
            return None
        for token in parts[1:]:
            if token.startswith("/"):
                return token
            if "/" in token and not token.startswith("http"):
                return token
        return None


class SyntheticTraceGenerator:
    """Generate OpenRange training traces from a simulated snapshot source."""

    def __init__(
        self,
        *,
        snapshot: SnapshotSpec | None = None,
        manifest: dict[str, Any] | None = None,
        builder: SnapshotBuilder | None = None,
        red_agent: RangeAgent | None = None,
        blue_agent: RangeAgent | None = None,
        active_roles: tuple[str, ...] = ("red", "blue"),
        tier: int = 1,
        max_steps: int = 30,
        randomize_flags: bool = True,
    ) -> None:
        if snapshot is None and manifest is None:
            raise ValueError("SyntheticTraceGenerator requires a snapshot or manifest")
        self._snapshot = snapshot.model_copy(deep=True) if snapshot is not None else None
        self._manifest = manifest
        self._builder = builder
        self._tier = tier
        self._max_steps = max_steps
        self._randomize_flags = randomize_flags
        self._active_roles = tuple(dict.fromkeys(active_roles)) or ("red", "blue")
        self.red_agent = red_agent or ScriptedRedAgent()
        self.blue_agent = blue_agent or ScriptedBlueAgent()

    @classmethod
    def from_manifest(
        cls,
        manifest: dict[str, Any],
        *,
        red_agent: RangeAgent | None = None,
        blue_agent: RangeAgent | None = None,
        active_roles: tuple[str, ...] = ("red", "blue"),
        builder: SnapshotBuilder | None = None,
        template_only: bool = True,
        builder_model: str | None = None,
        tier: int = 1,
        max_steps: int = 30,
        randomize_flags: bool = True,
    ) -> "SyntheticTraceGenerator":
        resolved_builder = builder
        if resolved_builder is None:
            if template_only:
                resolved_builder = TemplateOnlyBuilder()
            else:
                resolved_builder = LLMSnapshotBuilder(
                    model=builder_model or "azure/gpt-5.2-codex"
                )
        return cls(
            manifest=manifest,
            builder=resolved_builder,
            red_agent=red_agent,
            blue_agent=blue_agent,
            active_roles=active_roles,
            tier=tier,
            max_steps=max_steps,
            randomize_flags=randomize_flags,
        )

    def generate(
        self,
        *,
        num_traces: int = 10,
        seed: int | None = None,
    ) -> TrajectoryLogger:
        logger = TrajectoryLogger()
        for index in range(num_traces):
            episode_seed = None if seed is None else seed + index
            snapshot = self._materialize_snapshot(episode_seed)
            self._run_episode(
                snapshot=snapshot,
                logger=logger,
                episode_index=index,
                seed=episode_seed,
            )
        return logger

    def export_jsonl(
        self,
        path: str | Path,
        *,
        num_traces: int = 10,
        seed: int | None = None,
        reward_threshold: float = 0.0,
        roles: tuple[str, ...] = ("red", "blue"),
    ) -> tuple[TrajectoryLogger, int]:
        logger = self.generate(num_traces=num_traces, seed=seed)
        count = logger.export_jsonl(path, reward_threshold=reward_threshold, roles=roles)
        return logger, count

    def _materialize_snapshot(self, seed: int | None) -> SnapshotSpec:
        if self._snapshot is not None:
            return self._snapshot.model_copy(deep=True)
        if self._manifest is None or self._builder is None:
            raise RuntimeError("Synthetic trace generator is missing its manifest builder")

        context = BuildContext(seed=seed, tier=self._tier)
        snapshot = _run_async(self._builder.build(self._manifest, context))
        return snapshot

    def _run_episode(
        self,
        *,
        snapshot: SnapshotSpec,
        logger: TrajectoryLogger,
        episode_index: int,
        seed: int | None,
    ) -> None:
        env = SyntheticRangeEnvironment(
            randomize_flags=self._randomize_flags,
            max_steps=self._max_steps,
        )
        try:
            env.reset(
                snapshot=snapshot,
                episode_id=f"synth-{episode_index:04d}",
                seed=seed,
            )
            active_snapshot = env.snapshot
            if active_snapshot is None:
                raise RuntimeError("Synthetic environment failed to load a snapshot")

            red_briefing = _build_training_briefing(
                active_snapshot,
                role="red",
            )
            blue_briefing = _build_training_briefing(
                active_snapshot,
                role="blue",
            )

            if "red" in self._active_roles:
                self.red_agent.reset(briefing=red_briefing, role="red")
            if "blue" in self._active_roles:
                self.blue_agent.reset(briefing=blue_briefing, role="blue")

            snapshot_id = active_snapshot.topology.get("snapshot_id", f"synth-{episode_index:04d}")
            logger.start_episode(
                episode_id=f"synth-{episode_index:04d}",
                snapshot_id=snapshot_id,
                tier=env.state.tier,
                briefings={
                    "red": red_briefing,
                    "blue": blue_briefing,
                },
            )

            current_red_observation: str | RangeObservation = red_briefing
            current_blue_observation: str | RangeObservation = blue_briefing
            step = 0
            done = False
            last_obs: RangeObservation = RangeObservation(stdout=red_briefing)

            while step < self._max_steps and not done:
                if "red" in self._active_roles:
                    red_cmd = self.red_agent.act(current_red_observation)
                    red_obs = env.step(RangeAction(command=red_cmd, mode="red"))
                    red_output = _prefixed_output(
                        _observation_text(red_obs),
                        step=step + 1,
                    )
                    tool_name, tool_arguments = _infer_tool_call(red_cmd)
                    logger.log_turn(
                        role="red",
                        observation=red_output,
                        action=red_cmd,
                        reward=float(red_obs.reward or 0.0),
                        assistant_content=_render_trace_reasoning(
                            self.red_agent,
                            role="red",
                            command=red_cmd,
                        ),
                        tool_name=tool_name,
                        tool_arguments=tool_arguments,
                        tool_output=red_output,
                    )
                    step += 1
                    last_obs = red_obs
                    done = bool(red_obs.done)
                    current_red_observation = red_obs
                    current_blue_observation = _blue_stimulus(env)
                    if done or step >= self._max_steps:
                        break

                if "blue" not in self._active_roles:
                    continue

                blue_cmd = self.blue_agent.act(current_blue_observation)
                blue_obs = env.step(RangeAction(command=blue_cmd, mode="blue"))
                blue_output = _prefixed_output(
                    _observation_text(blue_obs),
                    step=step + 1,
                )
                tool_name, tool_arguments = _infer_tool_call(blue_cmd)
                logger.log_turn(
                    role="blue",
                    observation=blue_output,
                    action=blue_cmd,
                    reward=float(blue_obs.reward or 0.0),
                    assistant_content=_render_trace_reasoning(
                        self.blue_agent,
                        role="blue",
                        command=blue_cmd,
                    ),
                    tool_name=tool_name,
                    tool_arguments=tool_arguments,
                    tool_output=blue_output,
                )
                step += 1
                last_obs = blue_obs
                done = bool(blue_obs.done)
                current_blue_observation = blue_obs

            state = env.state
            outcome = self._episode_outcome(env)
            logger.end_episode(
                outcome=outcome,
                metrics={
                    "steps": state.step_count,
                    "flags_found": len(state.flags_found),
                    "red_actions": len(env.red_history),
                    "blue_actions": len(env.blue_history),
                    "done": bool(last_obs.done),
                    "source": "open_range.synthetic",
                    "ground_truth_flags": [flag.value for flag in active_snapshot.flags],
                    "optimal_steps": len(active_snapshot.golden_path),
                    "metadata": {
                        "generator": "synthetic",
                        "snapshot_origin": "manifest" if self._manifest is not None else "snapshot",
                    },
                },
            )
        finally:
            env.close()

    @staticmethod
    def _episode_outcome(env: SyntheticRangeEnvironment) -> str:
        if env.state.flags_found:
            return "flag_captured"
        if any(
            record.get("type") == "finding" or record.get("cmd_name") == "submit_finding"
            for record in env.blue_history
        ):
            return "blue_defended"
        return "timeout"


def build_teacher_agents(
    *,
    teacher_model: str | None = None,
    roles: tuple[str, ...] = ("red",),
    red_model: str | None = None,
    blue_model: str | None = None,
    red_bootstrap_messages: list[dict[str, Any]] | None = None,
    blue_bootstrap_messages: list[dict[str, Any]] | None = None,
    red_system_suffix: str = "",
    blue_system_suffix: str = "",
    temperature: float | None = 0.2,
    max_tokens: int = 512,
    **litellm_kwargs: Any,
) -> tuple[RangeAgent, RangeAgent]:
    """Construct teacher agents for the selected roles, scripted fallbacks otherwise."""
    red_suffix = "\n\n".join(
        block for block in (_SYNTHETIC_REASONING_GUIDE, red_system_suffix.strip()) if block
    )
    blue_suffix = "\n\n".join(
        block for block in (_SYNTHETIC_REASONING_GUIDE, blue_system_suffix.strip()) if block
    )

    if "red" in roles and (red_model or teacher_model):
        red_agent: RangeAgent = LLMRangeAgent(
            model=red_model or str(teacher_model),
            bootstrap_messages=red_bootstrap_messages,
            system_suffix=red_suffix,
            temperature=temperature,
            max_tokens=max_tokens,
            **litellm_kwargs,
        )
    else:
        red_agent = ScriptedRedAgent()

    if "blue" in roles and (blue_model or teacher_model):
        blue_agent: RangeAgent = LLMRangeAgent(
            model=blue_model or str(teacher_model),
            bootstrap_messages=blue_bootstrap_messages,
            system_suffix=blue_suffix,
            temperature=temperature,
            max_tokens=max_tokens,
            **litellm_kwargs,
        )
    else:
        blue_agent = ScriptedBlueAgent()

    return red_agent, blue_agent
