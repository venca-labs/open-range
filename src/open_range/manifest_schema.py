"""Pydantic models for OpenRange manifest validation.

A manifest declares the *world* of a cyber range: the fictional company, its
people, data, business processes, network topology, and the vulnerability
families the Builder may plant. This module lives under ``open_range`` so
installed tooling such as ``python -m open_range.lint`` does not depend on the
caller also importing the top-level ``manifests`` package.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Company context -- gives the Builder a story to build from
# ---------------------------------------------------------------------------


class Company(BaseModel):
    """The fictional company that owns this range."""

    name: str = Field(..., description="Company name, e.g. 'Meridian Health Partners'")
    domain: str = Field(..., description="Internal FQDN domain, e.g. 'meridianhealth.local'")
    industry: str = Field(..., description="Industry vertical, e.g. 'healthcare'")
    description: str = Field(
        ..., description="What the company does -- 2-3 sentences the Builder uses for narrative"
    )


class Department(BaseModel):
    """An organizational unit with its own access profile."""

    name: str
    description: str = ""
    hosts_accessed: list[str] = Field(
        default_factory=list,
        description="Hostnames staff in this dept routinely access",
    )


# ---------------------------------------------------------------------------
# People: users and NPC personas
# ---------------------------------------------------------------------------


class User(BaseModel):
    """A user account that exists in the range (LDAP/local)."""

    username: str
    full_name: str = ""
    department: str = ""
    role: str = ""
    email: str = ""
    hosts: list[str] = Field(
        default_factory=list,
        description="Hosts where this user has an account",
    )


class NPCProfile(BaseModel, extra="allow"):
    """An NPC persona the Builder should generate traffic and behavior for."""

    username: str = Field(..., description="Must reference a User.username")
    security_awareness: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="0=clueless, 1=CISO-level. Determines susceptibility to social engineering",
    )
    daily_activities: list[str] = Field(
        default_factory=list,
        description="What this person does all day -- generates realistic traffic patterns",
    )
    susceptibility: dict[str, float] = Field(
        default_factory=dict,
        description="Attack-type -> probability of falling for it, e.g. {'phishing_email': 0.7}",
    )


# ---------------------------------------------------------------------------
# Data and business processes -- tells the Builder what to protect
# ---------------------------------------------------------------------------


class DataAsset(BaseModel):
    """A piece of sensitive data that exists somewhere in the range."""

    name: str = Field(..., description="Human name, e.g. 'Patient referral records'")
    classification: Literal["public", "internal", "confidential", "restricted"] = "internal"
    host: str = Field(..., description="Host where this data lives")
    location: str = Field(
        default="", description="Path or service, e.g. '/srv/shares/hr' or 'mysql:app_db.patients'"
    )
    description: str = ""


class BusinessProcess(BaseModel):
    """A cross-service data flow the Builder should keep realistic."""

    name: str
    description: str = ""
    data_flow: list[str] = Field(
        default_factory=list,
        description="Ordered list of host:service hops, e.g. ['web:nginx', 'db:mysql', 'siem:rsyslog']",
    )


# ---------------------------------------------------------------------------
# Infrastructure realism -- software, config, and operational context
# ---------------------------------------------------------------------------


class TechStack(BaseModel, extra="allow"):
    """Specific software versions and known technical debt.

    Accepts both flat string fields and nested dicts for flexibility.
    """

    known_debt: list[str] = Field(default_factory=list)


class CredentialPolicy(BaseModel, extra="allow"):
    """How credentials work (and fail) in this organization.

    Accepts flexible formats: flat strings or structured dicts.
    """

    enforcement_gaps: list[Any] = Field(default_factory=list)


class MonitoringCoverage(BaseModel, extra="allow"):
    """What Blue can actually see -- and the blind spots Red can exploit."""

    logged: list[Any] = Field(default_factory=list)
    blind_spots: list[str] = Field(default_factory=list)
    alert_rules: list[Any] = Field(default_factory=list)
    retention_days: int = Field(default=90)


class TrustRelationship(BaseModel, extra="allow"):
    """Who trusts whom -- the social graph Red can exploit for lateral movement.

    Accepts 'from'/'to' (YAML-friendly) or 'source'/'target' field names.
    """

    type: str = Field(
        ..., description="Relationship type: reports_to, delegates_access, shares_credentials, trusts_email"
    )

    # Accept either naming convention
    source: str = ""
    target: str = ""

    # 'from' and 'to' are Python keywords, handle via model_validator
    @model_validator(mode="before")
    @classmethod
    def _normalize_field_names(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Normalize various naming conventions to source/target
            for src_key in ("from", "from_user"):
                if src_key in data and not data.get("source"):
                    data["source"] = data.pop(src_key)
            for tgt_key in ("to", "to_user"):
                if tgt_key in data and not data.get("target"):
                    data["target"] = data.pop(tgt_key)
            # Accept 'description', 'detail', or 'context' as the explanation field
            for alt in ("description", "detail"):
                if alt in data and "context" not in data:
                    data["context"] = data.pop(alt)
        return data

    context: str = Field(
        default="", description="Why this trust exists"
    )


class OperationalContext(BaseModel, extra="allow"):
    """How this company actually operates day-to-day.

    Accepts flexible formats for all fields.
    """

    recent_incidents: list[Any] = Field(default_factory=list)
    audit_findings: list[Any] = Field(default_factory=list)
    maintenance_windows: list[Any] | Any = Field(default_factory=list)
    vendor_access: list[Any] = Field(default_factory=list)
    recent_changes: list[Any] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Accept 'compliance' as alias for 'compliance_frameworks'
            if "compliance" in data and "compliance_frameworks" not in data:
                data["compliance_frameworks"] = data.pop("compliance")
            # Normalize maintenance_windows dict to list
            mw = data.get("maintenance_windows")
            if isinstance(mw, dict):
                data["maintenance_windows"] = [f"{k}: {v}" for k, v in mw.items()]
            elif isinstance(mw, str):
                data["maintenance_windows"] = [mw]
            # Normalize list-of-dicts to list-of-strings where needed
            for field in ("recent_incidents", "vendor_access", "recent_changes"):
                items = data.get(field, [])
                if items and isinstance(items[0], dict):
                    data[field] = [
                        item.get("description", "") or " | ".join(f"{k}: {v}" for k, v in item.items())
                        for item in items
                    ]
        return data

    compliance_frameworks: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Topology primitives
# ---------------------------------------------------------------------------


class ExposurePolicy(BaseModel):
    """Per-host exposure configuration."""

    level: Literal["public", "hidden", "authenticated", "misconfigured"] = "public"
    auth_required: bool = False
    notes: str = ""


class Host(BaseModel):
    """A single host (container) in the range topology."""

    name: str = Field(..., description="Unique hostname, e.g. 'web', 'db'")
    zone: str = Field(..., description="Network zone this host belongs to")
    purpose: str = Field(
        default="",
        description="Why this host exists in the company, e.g. 'Customer-facing referral portal'",
    )
    hostname: str = Field(
        default="",
        description="FQDN in the company domain, e.g. 'portal.meridianhealth.local'",
    )
    services: list[str] = Field(
        default_factory=list,
        description="Services running on this host, e.g. ['nginx', 'php', 'sshd']",
    )
    connects_to: list[str] = Field(
        default_factory=list,
        description="Hostnames this host initiates connections to",
    )
    os: str = Field(
        default="ubuntu:22.04",
        description="Base OS image for the container",
    )
    exposure: ExposurePolicy = Field(default_factory=ExposurePolicy)


class Network(BaseModel):
    """A named network zone with an optional CIDR."""

    name: str = Field(..., description="Zone name, e.g. 'dmz', 'internal'")
    cidr: str | None = Field(
        default=None,
        description="Subnet CIDR, e.g. '10.0.1.0/24'",
    )


class FirewallRule(BaseModel):
    """A directional firewall rule between two zones."""

    action: Literal["allow", "deny"] = Field(
        ..., description="Whether traffic is allowed or denied"
    )
    from_zone: str = Field(..., description="Source zone")
    to_zone: str = Field(..., description="Destination zone")
    ports: list[int] = Field(
        default_factory=list,
        description="TCP ports this rule applies to (empty = all ports)",
    )


class Topology(BaseModel):
    """Full network topology: hosts, networks, and firewall rules."""

    hosts: list[Host] = Field(..., min_length=1)
    networks: list[Network] = Field(..., min_length=1)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _hosts_reference_valid_zones(self) -> "Topology":
        zone_names = {n.name for n in self.networks}
        for host in self.hosts:
            if host.zone not in zone_names:
                raise ValueError(
                    f"Host '{host.name}' references zone '{host.zone}' "
                    f"which is not defined in networks: {sorted(zone_names)}"
                )
        return self

    @model_validator(mode="after")
    def _firewall_rules_reference_valid_zones(self) -> "Topology":
        zone_names = {n.name for n in self.networks}
        for rule in self.firewall_rules:
            for attr in ("from_zone", "to_zone"):
                zone = getattr(rule, attr)
                if zone not in zone_names:
                    raise ValueError(
                        f"Firewall rule references zone '{zone}' "
                        f"which is not defined in networks: {sorted(zone_names)}"
                    )
        return self


# ---------------------------------------------------------------------------
# Difficulty envelope
# ---------------------------------------------------------------------------


class Difficulty(BaseModel):
    """Difficulty constraints the Validator enforces on generated ranges."""

    max_steps: int = Field(
        ..., gt=0, description="Maximum golden-path steps allowed"
    )
    min_vulns: int = Field(
        default=1, ge=1, description="Minimum planted vulnerabilities"
    )
    max_vulns: int = Field(
        default=3, ge=1, description="Maximum planted vulnerabilities"
    )

    @model_validator(mode="after")
    def _min_le_max(self) -> "Difficulty":
        if self.min_vulns > self.max_vulns:
            raise ValueError(
                f"min_vulns ({self.min_vulns}) must be <= max_vulns ({self.max_vulns})"
            )
        return self


# ---------------------------------------------------------------------------
# Top-level manifest
# ---------------------------------------------------------------------------


class Manifest(BaseModel):
    """Top-level range manifest -- the contract between humans and the Builder.

    Required fields define the network and vuln envelope. Optional fields
    (company, users, NPCs, data, processes) provide narrative context that
    lets the Builder generate realistic, interconnected scenarios.
    """

    name: str = Field(..., description="Human-readable range name")
    tier: int = Field(..., ge=1, le=5, description="Complexity tier (1-5)")

    # Company context (optional but strongly encouraged)
    company: Company | None = None
    departments: list[Department] = Field(default_factory=list)
    users: list[User] = Field(default_factory=list)
    npc_personas: list[NPCProfile] = Field(default_factory=list)
    data_inventory: list[DataAsset] = Field(default_factory=list)
    business_processes: list[BusinessProcess] = Field(default_factory=list)

    # Infrastructure realism (optional -- enriches Builder context)
    tech_stack: TechStack | Any | None = None
    credential_policy: CredentialPolicy | Any | None = None
    monitoring_coverage: MonitoringCoverage | Any | None = None
    trust_relationships: list[TrustRelationship] = Field(default_factory=list)
    operational_context: OperationalContext | Any | None = None

    # Core topology and vuln envelope
    topology: Topology
    bug_families: list[str] = Field(
        ...,
        min_length=1,
        description="Vulnerability classes the Builder may plant (LLM generates details from these type names)",
    )
    task_families: list[str] = Field(
        default=["exploit", "investigate", "patch", "report"],
        description="Task types agents may be asked to perform",
    )
    difficulty: Difficulty


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_manifest(path: str | Path) -> Manifest:
    """Load a YAML manifest file and return a validated ``Manifest``.

    Raises ``FileNotFoundError`` if the file does not exist.
    Raises ``pydantic.ValidationError`` if the content is invalid.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    with open(path) as fh:
        raw = yaml.safe_load(fh)
    return Manifest(**raw)
