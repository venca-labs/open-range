"""Dynamic component resolution for OpenRange.

Loads Builder, NPC, and Validator implementations at startup from
dotted class paths specified in YAML config.
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
from typing import Any, Type

import yaml

from open_range.protocols import (
    NPCBehavior,
    SnapshotBuilder,
    ValidatorCheck,
)

# Default validator checks when none specified in config
DEFAULT_CHECKS: list[dict[str, Any]] = [
    {"class": "open_range.validator.build_boot.BuildBootCheck"},
    {"class": "open_range.validator.exploitability.ExploitabilityCheck"},
    {"class": "open_range.validator.patchability.PatchabilityCheck"},
    {"class": "open_range.validator.evidence.EvidenceSufficiencyCheck"},
    {"class": "open_range.validator.reward_grounding.RewardGroundingCheck"},
    {"class": "open_range.validator.isolation.IsolationLeakageCheck"},
]


def _missing_methods(instance: Any, protocol: Type) -> list[str]:
    """Return protocol method names missing from instance."""
    missing = []
    for name, method in inspect.getmembers(protocol, predicate=inspect.isfunction):
        if name.startswith("_"):
            continue
        if not hasattr(instance, name) or not callable(getattr(instance, name)):
            missing.append(name)
    return missing


def resolve_component(class_path: str, kwargs: dict, protocol: Type) -> Any:
    """Import class by dotted path, instantiate, verify protocol compliance.

    Args:
        class_path: Dotted Python class path (e.g. "open_range.builder.builder.LLMSnapshotBuilder")
        kwargs: Constructor keyword arguments
        protocol: Protocol class to check against

    Returns:
        Instantiated component satisfying the protocol.

    Raises:
        TypeError: If the class doesn't satisfy the protocol.
        ImportError: If the module can't be imported.
        AttributeError: If the class doesn't exist in the module.
    """
    module_name, _, class_name = class_path.rpartition(".")
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    instance = cls(**kwargs)
    if not isinstance(instance, protocol):
        missing = _missing_methods(instance, protocol)
        raise TypeError(
            f"{class_path} does not satisfy {protocol.__name__} protocol. "
            f"Missing methods: {missing}"
        )
    return instance


def load_agent_config(config_path: str) -> dict:
    """Load agent configuration from YAML file.

    Returns the 'agents' block from the config, or empty dict.
    """
    path = Path(config_path)
    if not path.exists():
        return {}
    with open(path) as f:
        config = yaml.safe_load(f) or {}
    return config.get("agents", {})


def build_components(
    config: dict,
) -> tuple[SnapshotBuilder, NPCBehavior, list[ValidatorCheck]]:
    """Resolve all infrastructure components from config dict.

    Args:
        config: The 'agents' block from openrange.yaml

    Returns:
        (builder, npc_behavior, validator_checks) tuple
    """
    builder_cfg = config.get("builder", {})
    builder = resolve_component(
        builder_cfg.get("class", "open_range.builder.builder.LLMSnapshotBuilder"),
        builder_cfg.get("kwargs", {}),
        SnapshotBuilder,
    )

    npc_cfg = config.get("npc_behavior", {})
    npc = resolve_component(
        npc_cfg.get("class", "open_range.builder.npc.npc_agent.NullNPCBehavior"),
        npc_cfg.get("kwargs", {}),
        NPCBehavior,
    )

    checks: list[ValidatorCheck] = []
    for check_cfg in config.get("validator_checks", DEFAULT_CHECKS):
        checks.append(
            resolve_component(
                check_cfg["class"],
                check_cfg.get("kwargs", {}),
                ValidatorCheck,
            )
        )

    return builder, npc, checks
