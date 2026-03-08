"""OpenRange validator -- 10-check admission gate for candidate snapshots."""

from open_range.validator.build_boot import BuildBootCheck
from open_range.validator.difficulty import DifficultyCheck
from open_range.validator.evidence import EvidenceCheck
from open_range.validator.exploitability import ExploitabilityCheck
from open_range.validator.isolation import IsolationCheck
from open_range.validator.npc_consistency import NPCConsistencyCheck
from open_range.validator.patchability import PatchabilityCheck
from open_range.validator.realism_review import RealismReviewCheck
from open_range.validator.reward_grounding import RewardGroundingCheck
from open_range.validator.task_feasibility import TaskFeasibilityCheck
from open_range.validator.validator import ValidationResult, ValidatorGate

__all__ = [
    "BuildBootCheck",
    "DifficultyCheck",
    "EvidenceCheck",
    "ExploitabilityCheck",
    "IsolationCheck",
    "NPCConsistencyCheck",
    "PatchabilityCheck",
    "RealismReviewCheck",
    "RewardGroundingCheck",
    "TaskFeasibilityCheck",
    "ValidationResult",
    "ValidatorGate",
]
