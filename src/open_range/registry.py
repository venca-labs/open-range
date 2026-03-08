"""World family registry: loads family metadata from manifests/registry.yaml.

Provides discovery, filtering, and lookup for available range families
so tooling (CLI, eval harness, curriculum) can enumerate what is available
without hard-coding manifest paths.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

# Default location relative to the repo root
_DEFAULT_REGISTRY = Path(__file__).resolve().parent.parent.parent / "manifests" / "registry.yaml"


class FamilyInfo(BaseModel):
    """Metadata for a single range family."""

    name: str = Field(..., description="Registry key, e.g. 'tier1_basic_enterprise'")
    display_name: str = Field(..., description="Human-friendly label")
    manifest: str = Field(..., description="YAML manifest filename (relative to manifests/)")
    description: str = Field(default="", description="One-line description")
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    difficulty: int = Field(default=1, ge=1, le=5, description="Difficulty rating 1-5")
    learning_goals: list[str] = Field(
        default_factory=list,
        description="What an agent should learn from this family",
    )


class Registry:
    """Loads and queries the family registry.

    Usage::

        reg = Registry.load()              # default path
        reg = Registry.load("path/to.yaml") # custom path
        families = reg.list_families()
        info = reg.get_family("tier1_basic_enterprise")
        easy = reg.filter_by_difficulty(1, 1)
        health = reg.filter_by_tag("healthcare")
    """

    def __init__(self, families: dict[str, FamilyInfo], registry_path: Path) -> None:
        self._families = families
        self._registry_path = registry_path

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Registry":
        """Load a registry YAML file.

        Args:
            path: Path to the registry YAML.  Defaults to
                  ``manifests/registry.yaml`` relative to the repo root.

        Raises:
            FileNotFoundError: If the registry file does not exist.
            ValueError: If the YAML is malformed or missing the ``families`` key.
        """
        resolved = Path(path) if path is not None else _DEFAULT_REGISTRY
        if not resolved.exists():
            raise FileNotFoundError(f"Registry file not found: {resolved}")

        with open(resolved) as fh:
            raw = yaml.safe_load(fh)

        if not isinstance(raw, dict) or "families" not in raw:
            raise ValueError(f"Registry YAML must contain a top-level 'families' key: {resolved}")

        families: dict[str, FamilyInfo] = {}
        for key, entry in raw["families"].items():
            if not isinstance(entry, dict):
                raise ValueError(f"Family '{key}' must be a mapping, got {type(entry).__name__}")
            families[key] = FamilyInfo(name=key, **entry)

        return cls(families=families, registry_path=resolved)

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def list_families(self) -> list[FamilyInfo]:
        """Return all registered families, sorted by difficulty then name."""
        return sorted(
            self._families.values(),
            key=lambda f: (f.difficulty, f.name),
        )

    def get_family(self, name: str) -> FamilyInfo:
        """Look up a family by its registry key.

        Raises:
            KeyError: If the name is not in the registry.
        """
        if name not in self._families:
            raise KeyError(
                f"Unknown family '{name}'. "
                f"Available: {sorted(self._families.keys())}"
            )
        return self._families[name]

    def filter_by_tag(self, tag: str) -> list[FamilyInfo]:
        """Return families whose tags contain *tag* (case-insensitive)."""
        tag_lower = tag.lower()
        return sorted(
            [f for f in self._families.values() if tag_lower in [t.lower() for t in f.tags]],
            key=lambda f: (f.difficulty, f.name),
        )

    def filter_by_difficulty(self, min_difficulty: int = 1, max_difficulty: int = 5) -> list[FamilyInfo]:
        """Return families within the given difficulty range (inclusive)."""
        return sorted(
            [
                f
                for f in self._families.values()
                if min_difficulty <= f.difficulty <= max_difficulty
            ],
            key=lambda f: (f.difficulty, f.name),
        )

    @property
    def manifests_dir(self) -> Path:
        """Directory containing the manifest YAML files."""
        return self._registry_path.parent

    def __len__(self) -> int:
        return len(self._families)

    def __contains__(self, name: str) -> bool:
        return name in self._families

    def __repr__(self) -> str:
        return f"Registry({len(self._families)} families from {self._registry_path})"
