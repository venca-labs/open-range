"""NPC contract models shared across runtime and builder code."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AsyncModality = Literal["email", "chat"]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NPCBackstory(_Frozen):
    """Work-focused biography for an NPC."""

    full_name: str = ""
    location: str = ""
    working_hours: str = ""
    work_style: str = ""
    communication_style: str = ""
    projects: tuple[str, ...] = ()
    responsibilities: str = ""
    friends: tuple[str, ...] = ()
    preferred_modality: AsyncModality = "email"
    background: str = ""
    years_at_company: int = Field(default=2, ge=0)


class NPCPersonality(_Frozen):
    """Behavioral traits that influence NPC decisions and communication."""

    mood: str = "focused"
    disposition: str = "cooperative"
    interpersonal_style: str = "casual"
    work_ethic: str = "diligent"
    risk_tolerance: float = Field(default=0.5, ge=0.0, le=1.0)
    chattiness: float = Field(default=0.5, ge=0.0, le=1.0)


class NPCProfile(_Frozen):
    """Aggregated identity for a single NPC persona."""

    backstory: NPCBackstory = Field(default_factory=NPCBackstory)
    personality: NPCPersonality = Field(default_factory=NPCPersonality)
