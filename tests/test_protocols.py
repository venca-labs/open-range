"""Tests for agent protocols and dynamic component resolution."""

import pytest

from open_range.protocols import (
    BuildContext,
    SnapshotBuilder,
    NPCBehavior,
    ValidatorCheck,
    SnapshotSpec,
    NPCPersona,
    Stimulus,
    NPCAction,
    CheckResult,
    ContainerSet,
)
from open_range.resolve import resolve_component


class TestProtocolCompliance:
    """Builder implementations satisfy the SnapshotBuilder protocol."""

    def test_template_only_builder_satisfies_protocol(self):
        from open_range.builder.builder import TemplateOnlyBuilder

        b = TemplateOnlyBuilder()
        assert isinstance(b, SnapshotBuilder)

    def test_file_builder_satisfies_protocol(self):
        from open_range.builder.builder import FileBuilder

        b = FileBuilder()
        assert isinstance(b, SnapshotBuilder)

    def test_llm_snapshot_builder_satisfies_protocol(self):
        from open_range.builder.builder import LLMSnapshotBuilder

        b = LLMSnapshotBuilder()
        assert isinstance(b, SnapshotBuilder)


class TestValidatorCheckProtocol:
    """Validator check classes satisfy ValidatorCheck protocol."""

    def test_build_boot_check(self):
        from open_range.validator.build_boot import BuildBootCheck

        assert isinstance(BuildBootCheck(), ValidatorCheck)

    def test_exploitability_check(self):
        from open_range.validator.exploitability import ExploitabilityCheck

        assert isinstance(ExploitabilityCheck(), ValidatorCheck)

    def test_difficulty_check(self):
        from open_range.validator.difficulty import DifficultyCheck

        assert isinstance(DifficultyCheck(), ValidatorCheck)

    def test_isolation_check(self):
        from open_range.validator.isolation import IsolationCheck

        assert isinstance(IsolationCheck(), ValidatorCheck)

    def test_evidence_check(self):
        from open_range.validator.evidence import EvidenceCheck

        assert isinstance(EvidenceCheck(), ValidatorCheck)

    def test_npc_consistency_check(self):
        from open_range.validator.npc_consistency import NPCConsistencyCheck

        assert isinstance(NPCConsistencyCheck(), ValidatorCheck)


class TestResolveComponent:
    """resolve_component imports and protocol-checks correctly."""

    def test_resolve_valid_builder(self):
        instance = resolve_component(
            "open_range.builder.builder.TemplateOnlyBuilder",
            {},
            SnapshotBuilder,
        )
        assert isinstance(instance, SnapshotBuilder)

    def test_resolve_valid_validator_check(self):
        instance = resolve_component(
            "open_range.validator.build_boot.BuildBootCheck",
            {},
            ValidatorCheck,
        )
        assert isinstance(instance, ValidatorCheck)

    def test_resolve_nonexistent_module_raises(self):
        with pytest.raises(ModuleNotFoundError):
            resolve_component(
                "nonexistent.module.FakeClass",
                {},
                SnapshotBuilder,
            )

    def test_resolve_nonexistent_class_raises(self):
        with pytest.raises(AttributeError):
            resolve_component(
                "open_range.builder.builder.DoesNotExist",
                {},
                SnapshotBuilder,
            )

    def test_resolve_non_compliant_class_raises(self):
        """A class that doesn't satisfy the protocol raises TypeError."""
        with pytest.raises(TypeError, match="does not satisfy"):
            resolve_component(
                "open_range.server.models.RangeAction",
                {"command": "x", "mode": "red"},
                SnapshotBuilder,
            )


class TestBuildContext:
    """BuildContext model basics."""

    def test_defaults(self):
        ctx = BuildContext()
        assert ctx.tier == 1
        assert ctx.seed is None
        assert ctx.previous_vuln_classes == []
        assert ctx.red_solve_rate == 0.0

    def test_with_values(self):
        ctx = BuildContext(
            seed=42,
            tier=3,
            previous_vuln_classes=["sqli", "xss"],
            weak_areas=["ssrf"],
        )
        assert ctx.seed == 42
        assert ctx.tier == 3
        assert "sqli" in ctx.previous_vuln_classes
