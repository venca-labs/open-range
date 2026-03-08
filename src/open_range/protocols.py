"""Agent protocols and shared Pydantic models for OpenRange.

Three pluggable infrastructure components:
- SnapshotBuilder: generates candidate snapshot specs from manifests
- NPCBehavior: decides NPC response to stimuli
- ValidatorCheck: single admission check in the validation pipeline
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class BuildContext(BaseModel):
    """Runtime context passed to the Builder on each build() call."""

    seed: int | None = None
    tier: int = 1
    previous_vuln_classes: list[str] = Field(default_factory=list)
    red_solve_rate: float = 0.0
    blue_detect_rate: float = 0.0
    weak_areas: list[str] = Field(default_factory=list)
    recent_attack_surfaces: list[str] = Field(default_factory=list)
    episode_count: int = 0

    # Narrative guidance from curriculum
    narrative_hints: list[str] = Field(
        default_factory=list,
        description="Curriculum-driven hints, e.g. 'include lateral movement via credential reuse'",
    )
    require_chain_length: int = Field(
        default=0,
        description="If > 0, force multi-hop exploit chains of at least this length",
    )
    focus_layer: str = Field(
        default="",
        description="Which realism layer to emphasize: 'infra', 'app', 'identity', 'process'",
    )


class Vulnerability(BaseModel):
    """Single planted vulnerability in the truth graph."""

    id: str
    type: str  # e.g. sqli, xss, idor, ssrf
    host: str
    service: str = ""
    injection_point: str = ""
    vulnerable_code: str | dict[str, str] = ""  # str or {file_path: snippet}
    root_cause: str = ""
    blast_radius: str = ""
    remediation: str = ""


class ExploitStep(BaseModel):
    """Single step in an exploit chain."""

    vuln_id: str
    command: str
    description: str = ""


class TruthGraph(BaseModel):
    """Ground truth about planted vulnerabilities and exploit chains."""

    vulns: list[Vulnerability] = Field(default_factory=list)
    exploit_chain: list[ExploitStep] = Field(default_factory=list)


class GoldenPathStep(BaseModel):
    """Single step in the golden path walkthrough."""

    step: int
    command: str
    expect_in_stdout: str = ""
    host: str = "attacker"
    description: str = ""


class FlagSpec(BaseModel):
    """Flag definition: value and where it lives."""

    id: str
    value: str
    path: str
    host: str


class EvidenceItem(BaseModel):
    """Expected evidence artifact for Blue to find."""

    type: str  # log_entry, alert, file
    location: str
    pattern: str = ""


class NPCPersona(BaseModel):
    """NPC persona card for LLM-driven NPC behavior."""

    name: str
    role: str = ""
    department: str = ""
    reports_to: str = ""
    communication_style: str = ""
    security_awareness: float = 0.5  # 0.0-1.0
    susceptibility: dict[str, float] = Field(default_factory=dict)
    routine: dict[str, Any] = Field(default_factory=dict)
    accounts: dict[str, str] = Field(default_factory=dict)


class NPCTrafficSpec(BaseModel):
    """NPC traffic configuration."""

    level: int = 0  # 0=shell scripts, 1=LLM personas
    rate_lambda: float = 10.0  # requests/minute
    scripts: list[str] = Field(default_factory=list)


class TaskType(str, Enum):
    """Types of tasks agents can be assigned."""

    EXPLOIT = "exploit"
    INVESTIGATE = "investigate"
    PATCH = "patch"
    REPORT = "report"
    ENDPOINT_QUERY = "endpoint_query"
    MULTI_STEP = "multi_step"


class TaskSpec(BaseModel):
    """Agent-facing task descriptions (no leakage of internals)."""

    red_briefing: str = ""
    blue_briefing: str = ""
    task_type: str = "exploit"  # Use str not enum for flexibility
    milestones: list[str] = Field(default_factory=list)  # For multi_step tasks
    success_conditions: list[dict[str, Any]] = Field(
        default_factory=list,
    )  # [{type: "flag", value: "..."}, {type: "endpoint", url: "...", expect: "..."}]


class SnapshotSpec(BaseModel):
    """Complete specification for a generated range snapshot."""

    topology: dict[str, Any] = Field(default_factory=dict)
    truth_graph: TruthGraph = Field(default_factory=TruthGraph)
    golden_path: list[GoldenPathStep] = Field(default_factory=list)
    flags: list[FlagSpec] = Field(default_factory=list)
    evidence_spec: list[EvidenceItem] = Field(default_factory=list)
    npc_personas: list[NPCPersona] = Field(default_factory=list)
    npc_traffic: NPCTrafficSpec = Field(default_factory=NPCTrafficSpec)
    task: TaskSpec = Field(default_factory=TaskSpec)
    compose: dict[str, Any] = Field(default_factory=dict)  # rendered docker-compose
    files: dict[str, str] = Field(default_factory=dict)  # path -> content


class Stimulus(BaseModel):
    """Incoming stimulus for an NPC to react to."""

    type: str = "email"  # email, chat, file_access, voice
    sender: str = ""
    subject: str = ""
    content: str = ""
    attachments: list[str] = Field(default_factory=list)
    plausibility: float = 0.5  # 0.0-1.0


class NPCAction(BaseModel):
    """NPC's decided response to a stimulus."""

    action: str = "ignore"  # click_link, open_attachment, reply, share_credentials,
    #                         ignore, report_to_IT, forward
    response_content: str = ""
    side_effects: list[str] = Field(default_factory=list)


class CheckResult(BaseModel):
    """Result of a single validator check."""

    name: str = ""
    passed: bool = False
    time_s: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    advisory: bool = False  # if True, failure triggers retry but never blocks


class ContainerSet(BaseModel):
    """Handle to live Docker containers for a snapshot."""

    project_name: str = ""
    container_ids: dict[str, str] = Field(default_factory=dict)  # service -> id

    class Config:
        arbitrary_types_allowed = True

    async def exec(self, container: str, cmd: str, timeout: float = 30.0) -> str:
        """Run *cmd* inside *container* and return combined stdout+stderr."""
        import asyncio

        cid = self.container_ids.get(container, container)
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", cid, "sh", "-c", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return "<timeout>"
        return (stdout or b"").decode(errors="replace")

    async def is_healthy(self, container: str) -> bool:
        """Return True when *container* is running and its healthcheck passes."""
        import asyncio

        cid = self.container_ids.get(container, container)
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--format", "{{.State.Status}}", cid,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        status = (stdout or b"").decode().strip()
        return status == "running"

    async def cp(self, container: str, src: str, dest: str) -> None:
        """Copy a file into a container: ``docker cp src container:dest``."""
        import asyncio

        cid = self.container_ids.get(container, container)
        proc = await asyncio.create_subprocess_exec(
            "docker", "cp", src, f"{cid}:{dest}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class SnapshotBuilder(Protocol):
    """Generate a candidate snapshot spec from a manifest."""

    async def build(
        self,
        manifest: dict,
        context: BuildContext,
    ) -> SnapshotSpec: ...


@runtime_checkable
class NPCBehavior(Protocol):
    """Decide how an NPC responds to a stimulus."""

    async def decide(
        self,
        persona: NPCPersona,
        stimulus: Stimulus,
    ) -> NPCAction: ...


@runtime_checkable
class ValidatorCheck(Protocol):
    """Single check in the validator admission pipeline."""

    async def check(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
    ) -> CheckResult: ...
