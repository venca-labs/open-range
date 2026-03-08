"""Managed snapshot runtime for the shipped OpenRange server process.

This module keeps the OpenEnv-facing environment instances lightweight while a
single shared manager owns the admitted snapshot pool, generation loop, and
episode feedback.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import shutil
import subprocess as sp
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from open_range.builder.builder import LLMSnapshotBuilder, TemplateOnlyBuilder
from open_range.builder.mutator import Mutator
from open_range.builder.renderer import SnapshotRenderer
from open_range.builder.snapshot_store import SnapshotStore
from open_range.protocols import (
    BuildContext,
    CheckResult,
    ContainerSet,
    SnapshotBuilder,
    SnapshotSpec,
)
from open_range.server.models import RangeState
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

logger = logging.getLogger(__name__)

_DEFAULT_MANIFEST = ("manifests", "tier1_basic.yaml")
_VALIDATOR_PROFILE_ALIASES = {
    "light": "offline",
    "static": "offline",
    "full": "training",
    "strict": "training",
}
_LIVE_VALIDATOR_PROFILES = {"training"}


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _candidate_roots() -> list[Path]:
    roots: list[Path] = []
    cwd = Path.cwd()
    roots.append(cwd)
    file_path = Path(__file__).resolve()
    roots.extend(file_path.parents[:6])

    unique: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        unique.append(root)
    return unique


def _resolve_default_manifest_path() -> Path:
    for root in _candidate_roots():
        candidate = root.joinpath(*_DEFAULT_MANIFEST)
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Could not locate the default manifest. "
        "Set OPENRANGE_RUNTIME_MANIFEST to an explicit YAML path."
    )


def _resolve_store_dir(store_dir: str | Path | None) -> Path:
    if store_dir is None:
        return Path(os.getenv("OPENRANGE_SNAPSHOT_DIR", "snapshots")).resolve()
    return Path(store_dir).resolve()


def _run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine from sync code.

    The runtime is used from sync OpenEnv environment methods and a background
    thread, so we provide a conservative bridge here.
    """

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}
    error: list[BaseException] = []

    def _runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001
            error.append(exc)

    thread = threading.Thread(target=_runner, name="openrange-coro-bridge")
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result.get("value")


@dataclass(slots=True)
class EpisodeOutcome:
    snapshot_id: str | None
    red_solved: bool
    blue_detected: bool
    steps: int
    weak_areas: list[str] = field(default_factory=list)
    completed: bool = False
    recorded_at: float = field(default_factory=time.time)


class CurriculumTracker:
    """Tiny in-process curriculum memory for future snapshot generation."""

    def __init__(self, max_history: int = 100) -> None:
        self.max_history = max_history
        self._history: list[EpisodeOutcome] = []
        self._lock = threading.Lock()

    def record(self, outcome: EpisodeOutcome) -> None:
        with self._lock:
            self._history.append(outcome)
            if len(self._history) > self.max_history:
                del self._history[: len(self._history) - self.max_history]

    def build_context(self, *, seed: int, tier: int) -> BuildContext:
        with self._lock:
            history = list(self._history)

        completed = [o for o in history if o.completed]
        red_solve_rate = (
            sum(1 for o in completed if o.red_solved) / len(completed)
            if completed
            else 0.0
        )
        blue_detect_rate = (
            sum(1 for o in completed if o.blue_detected) / len(completed)
            if completed
            else 0.0
        )

        weak_counts: dict[str, int] = {}
        for outcome in completed:
            if outcome.red_solved:
                continue
            for area in outcome.weak_areas:
                weak_counts[area] = weak_counts.get(area, 0) + 1

        weak_areas = [
            area
            for area, _count in sorted(
                weak_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )[:3]
        ]

        return BuildContext(
            seed=seed,
            tier=tier,
            red_solve_rate=red_solve_rate,
            blue_detect_rate=blue_detect_rate,
            weak_areas=weak_areas,
        )

    @property
    def history(self) -> list[EpisodeOutcome]:
        with self._lock:
            return list(self._history)


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    snapshot_id: str
    snapshot: SnapshotSpec


class StructuralSnapshotCheck:
    """Lightweight admission check for the shipped no-Docker runtime path."""

    async def check(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
    ) -> CheckResult:
        issues: list[str] = []
        if not snapshot.truth_graph.vulns:
            issues.append("truth_graph has no vulns")
        if not snapshot.golden_path:
            issues.append("golden_path is empty")
        if not snapshot.flags:
            issues.append("flags are empty")
        if not snapshot.task.red_briefing or not snapshot.task.blue_briefing:
            issues.append("task briefings are missing")
        for briefing_name, text in (
            ("red_briefing", snapshot.task.red_briefing),
            ("blue_briefing", snapshot.task.blue_briefing),
        ):
            for flag in snapshot.flags:
                if flag.value and flag.value in text:
                    issues.append(f"flag leaked in {briefing_name}")
            for step in snapshot.golden_path:
                if len(step.command) > 20 and step.command in text:
                    issues.append(f"golden-path command leaked in {briefing_name}")

        passed = len(issues) == 0
        return CheckResult(
            name="structural_snapshot",
            passed=passed,
            details={"issues": issues},
            error="" if passed else "; ".join(issues),
        )


def _default_builder() -> SnapshotBuilder:
    mode = os.getenv("OPENRANGE_RUNTIME_BUILDER", "template").strip().lower()
    if mode == "template":
        return TemplateOnlyBuilder()
    if mode == "llm":
        return LLMSnapshotBuilder()
    raise ValueError(
        f"Unsupported OPENRANGE_RUNTIME_BUILDER={mode!r}. "
        "Expected 'template' or 'llm'."
    )


def _normalize_validator_profile(profile: str | None) -> str:
    normalized = (profile or "offline").strip().lower()
    normalized = _VALIDATOR_PROFILE_ALIASES.get(normalized, normalized)
    if normalized not in {"offline", "training"}:
        raise ValueError(
            f"Unsupported validator profile {profile!r}. "
            "Expected 'offline' or 'training'."
        )
    return normalized


def _build_validator(profile: str) -> ValidatorGate:
    normalized = _normalize_validator_profile(profile)
    if normalized == "offline":
        return ValidatorGate(
            [
                StructuralSnapshotCheck(),
                TaskFeasibilityCheck(),
            ]
        )

    return ValidatorGate(
        [
            BuildBootCheck(),
            ExploitabilityCheck(),
            PatchabilityCheck(),
            EvidenceCheck(),
            RewardGroundingCheck(),
            IsolationCheck(),
            TaskFeasibilityCheck(),
            DifficultyCheck(),
            NPCConsistencyCheck(),
            RealismReviewCheck(),
        ]
    )


class ManagedSnapshotRuntime:
    """Shared server-side manager for admitted snapshots."""

    def __init__(
        self,
        *,
        manifest: dict[str, Any] | None = None,
        manifest_path: str | Path | None = None,
        store_dir: str | Path | None = None,
        builder: SnapshotBuilder | None = None,
        validator: ValidatorGate | None = None,
        validator_profile: str | None = None,
        pool_size: int = 3,
        selection_strategy: str = "random",
        refill_enabled: bool = False,
        refill_interval_s: float = 2.0,
        generation_retries: int = 3,
    ) -> None:
        self.manifest_path = (
            Path(manifest_path).resolve()
            if manifest_path is not None
            else _resolve_default_manifest_path()
        )
        self.manifest = manifest or self._load_manifest(self.manifest_path)
        self.store_dir = _resolve_store_dir(store_dir)
        self.store = SnapshotStore(str(self.store_dir))
        self.builder = builder or _default_builder()
        self.mutator = Mutator(self.builder)
        self.validator_profile = _normalize_validator_profile(
            validator_profile or os.getenv("OPENRANGE_RUNTIME_VALIDATOR_PROFILE", "offline")
        )
        self.validator = validator or _build_validator(self.validator_profile)
        self.renderer = SnapshotRenderer()
        self.curriculum = CurriculumTracker()
        self.pool_size = max(1, pool_size)
        self.selection_strategy = selection_strategy
        self.refill_enabled = refill_enabled
        self.refill_interval_s = max(0.25, refill_interval_s)
        self.generation_retries = max(1, generation_retries)

        self._lock = threading.RLock()
        self._refill_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._started = False
        self._generation_counter = 0

    @classmethod
    def from_env(cls) -> "ManagedSnapshotRuntime":
        return cls(
            manifest_path=os.getenv("OPENRANGE_RUNTIME_MANIFEST"),
            store_dir=os.getenv("OPENRANGE_SNAPSHOT_DIR"),
            validator_profile=os.getenv("OPENRANGE_RUNTIME_VALIDATOR_PROFILE", "offline"),
            pool_size=_env_int("OPENRANGE_SNAPSHOT_POOL_SIZE", 3),
            selection_strategy=os.getenv("OPENRANGE_SNAPSHOT_SELECTION", "random"),
            refill_enabled=_env_flag("OPENRANGE_ENABLE_MANAGED_REFILL", default=False),
            refill_interval_s=float(os.getenv("OPENRANGE_REFILL_INTERVAL_S", "2.0")),
            generation_retries=_env_int("OPENRANGE_GENERATION_RETRIES", 3),
        )

    @staticmethod
    def _load_manifest(path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise TypeError(f"Manifest at {path} did not parse to a mapping")
        return data

    def start(self) -> None:
        with self._lock:
            if self._started:
                return

            existing = self.snapshot_count()
            if existing < self.pool_size:
                self._top_up_pool(self.pool_size - existing)
            self._ensure_existing_artifacts()

            available = self.snapshot_count()
            if available == 0:
                raise RuntimeError(
                    "ManagedSnapshotRuntime could not load or generate any admitted snapshots"
                )

            if self.refill_enabled:
                self._stop_event.clear()
                self._refill_thread = threading.Thread(
                    target=self._refill_loop,
                    name="openrange-runtime-refill",
                    daemon=True,
                )
                self._refill_thread.start()

            self._started = True
            logger.info(
                "ManagedSnapshotRuntime started with %d admitted snapshot(s) in %s",
                available,
                self.store_dir,
            )

    def stop(self) -> None:
        with self._lock:
            if not self._started:
                return
            self._stop_event.set()
            thread = self._refill_thread
            self._refill_thread = None
            self._started = False

        if thread is not None:
            thread.join(timeout=self.refill_interval_s * 2)

    def acquire_snapshot(self, *, snapshot_id: str | None = None) -> RuntimeSnapshot:
        self.start()
        if snapshot_id:
            return self.get_snapshot(snapshot_id)

        stored = _run_coro_sync(self.store.select_entry(strategy=self.selection_strategy))
        return RuntimeSnapshot(snapshot_id=stored.snapshot_id, snapshot=stored.snapshot)

    def get_snapshot(self, snapshot_id: str) -> RuntimeSnapshot:
        self.start()
        stored = _run_coro_sync(self.store.get_entry(snapshot_id))
        return RuntimeSnapshot(snapshot_id=stored.snapshot_id, snapshot=stored.snapshot)

    def list_snapshots(self) -> list[dict[str, Any]]:
        return _run_coro_sync(self.store.list_snapshots())

    def snapshot_count(self) -> int:
        return len(self.list_snapshots())

    def status(self) -> dict[str, Any]:
        return {
            "manifest_path": str(self.manifest_path),
            "store_dir": str(self.store_dir),
            "pool_size": self.pool_size,
            "selection_strategy": self.selection_strategy,
            "validator_profile": self.validator_profile,
            "refill_enabled": self.refill_enabled,
            "snapshot_count": self.snapshot_count(),
            "started": self._started,
        }

    def record_episode_result(
        self,
        *,
        snapshot_id: str | None,
        snapshot: SnapshotSpec | None,
        state: RangeState,
        red_history: list[dict[str, Any]],
        blue_history: list[dict[str, Any]],
        completed: bool,
    ) -> None:
        if snapshot is None:
            return

        total_flags = len(snapshot.flags)
        red_solved = total_flags > 0 and len(state.flags_found) >= total_flags
        blue_detected = any(
            record.get("type") == "finding" or record.get("cmd_name") == "submit_finding"
            for record in blue_history
        )
        weak_areas = []
        if not red_solved:
            weak_areas = [v.type for v in snapshot.truth_graph.vulns]

        self.curriculum.record(
            EpisodeOutcome(
                snapshot_id=snapshot_id,
                red_solved=red_solved,
                blue_detected=blue_detected,
                steps=state.step_count,
                weak_areas=weak_areas,
                completed=completed,
            )
        )

    def _refill_loop(self) -> None:
        while not self._stop_event.wait(self.refill_interval_s):
            try:
                missing = self.pool_size - self.snapshot_count()
                if missing > 0:
                    self._top_up_pool(missing)
            except Exception as exc:  # noqa: BLE001
                logger.warning("ManagedSnapshotRuntime refill failed: %s", exc)

    def _top_up_pool(self, missing: int) -> None:
        for _ in range(max(0, missing)):
            self._generate_and_store_snapshot()

    def _ensure_existing_artifacts(self) -> None:
        for meta in self.list_snapshots():
            snapshot_id = str(meta.get("snapshot_id", ""))
            if not snapshot_id:
                continue
            artifacts_dir = self._artifacts_dir(snapshot_id)
            if artifacts_dir.exists():
                continue
            stored = _run_coro_sync(self.store.get_entry(snapshot_id))
            materialized = self._materialize_snapshot(stored.snapshot, snapshot_id)
            _run_coro_sync(self.store.store(materialized, snapshot_id=snapshot_id))

    def _generate_and_store_snapshot(self) -> str:
        last_error: str | None = None
        for attempt in range(1, self.generation_retries + 1):
            context = self._build_context()
            snapshot = _run_coro_sync(
                self.mutator.mutate(
                    self.manifest,
                    context=context,
                    error={"message": last_error} if last_error else None,
                )
            )
            validation = self._validate_snapshot(snapshot)
            if validation.passed:
                snapshot_id = self._snapshot_id(snapshot)
                materialized = self._materialize_snapshot(snapshot, snapshot_id)
                snapshot_id = _run_coro_sync(
                    self.store.store(materialized, snapshot_id=snapshot_id)
                )
                logger.info(
                    "ManagedSnapshotRuntime admitted snapshot %s on attempt %d",
                    snapshot_id,
                    attempt,
                )
                return snapshot_id

            last_error = self._validation_error(validation)
            logger.warning(
                "ManagedSnapshotRuntime rejected candidate on attempt %d: %s",
                attempt,
                last_error,
            )

        raise RuntimeError(
            "ManagedSnapshotRuntime failed to admit a snapshot after "
            f"{self.generation_retries} attempt(s): {last_error}"
        )

    def _build_context(self) -> BuildContext:
        seed = self._generation_counter
        self._generation_counter += 1
        tier = int(self.manifest.get("tier", 1) or 1)
        context = self.curriculum.build_context(seed=seed, tier=tier)
        context.episode_count = self.mutator.episode_count
        return context

    def _validate_snapshot(self, snapshot: SnapshotSpec) -> ValidationResult:
        if self.validator_profile not in _LIVE_VALIDATOR_PROFILES:
            return _run_coro_sync(self.validator.validate(snapshot, ContainerSet()))
        return self._validate_snapshot_live(snapshot)

    def _validate_snapshot_live(self, snapshot: SnapshotSpec) -> ValidationResult:
        snapshot_id = self._snapshot_id(snapshot)
        project_name = self._project_name(snapshot_id)

        with tempfile.TemporaryDirectory(prefix=f"openrange-validate-{snapshot_id}-") as temp_dir:
            snapshot_dir = Path(temp_dir)
            rendered = snapshot.model_copy(deep=True)
            topology = dict(rendered.topology)
            topology["snapshot_id"] = snapshot_id
            rendered.topology = topology
            self.renderer.render(rendered, snapshot_dir)

            compose_file = snapshot_dir / "docker-compose.yml"
            up_result = self._compose_up(snapshot_dir, compose_file, project_name)
            if up_result is not None:
                return up_result

            try:
                containers = self._discover_containers(project_name)
                self._deploy_snapshot_artifacts(rendered, containers, snapshot_dir)
                return _run_coro_sync(self.validator.validate(rendered, containers))
            except Exception as exc:  # noqa: BLE001
                return ValidationResult(
                    passed=False,
                    checks=[
                        CheckResult(
                            name="live_validation",
                            passed=False,
                            error=str(exc),
                        )
                    ],
                )
            finally:
                self._compose_down(snapshot_dir, compose_file, project_name)

    def _project_name(self, snapshot_id: str) -> str:
        safe = "".join(ch if ch.isalnum() else "-" for ch in snapshot_id.lower()).strip("-")
        safe = safe[:40] or "snapshot"
        return f"openrange-{safe}"

    def _compose_up(
        self,
        snapshot_dir: Path,
        compose_file: Path,
        project_name: str,
    ) -> ValidationResult | None:
        try:
            proc = sp.run(
                [
                    "docker",
                    "compose",
                    "-p",
                    project_name,
                    "-f",
                    str(compose_file),
                    "up",
                    "-d",
                    "--build",
                ],
                cwd=str(snapshot_dir),
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except FileNotFoundError as exc:
            return ValidationResult(
                passed=False,
                checks=[CheckResult(name="build_boot", passed=False, error=str(exc))],
            )
        except sp.TimeoutExpired:
            return ValidationResult(
                passed=False,
                checks=[
                    CheckResult(
                        name="build_boot",
                        passed=False,
                        error="docker compose up timed out after 300s",
                    )
                ],
            )

        if proc.returncode != 0:
            error = (proc.stderr or proc.stdout or "").strip() or "docker compose up failed"
            return ValidationResult(
                passed=False,
                checks=[CheckResult(name="build_boot", passed=False, error=error)],
            )
        return None

    def _compose_down(self, snapshot_dir: Path, compose_file: Path, project_name: str) -> None:
        try:
            sp.run(
                [
                    "docker",
                    "compose",
                    "-p",
                    project_name,
                    "-f",
                    str(compose_file),
                    "down",
                    "-v",
                    "--remove-orphans",
                ],
                cwd=str(snapshot_dir),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except Exception:  # noqa: BLE001
            logger.warning("Failed to tear down validation project %s", project_name)

    def _discover_containers(self, project_name: str) -> ContainerSet:
        proc = sp.run(
            [
                "docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--format",
                "{{.Label \"com.docker.compose.service\"}} {{.Names}}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "docker ps failed")

        container_ids: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            service, _, container_name = line.partition(" ")
            if service and container_name:
                container_ids[service.strip()] = container_name.strip()

        if not container_ids:
            raise RuntimeError(f"no running containers found for project {project_name}")
        return ContainerSet(project_name=project_name, container_ids=container_ids)

    def _deploy_snapshot_artifacts(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
        snapshot_dir: Path,
    ) -> None:
        _run_coro_sync(self._deploy_snapshot_artifacts_async(snapshot, containers, snapshot_dir))

    async def _deploy_snapshot_artifacts_async(
        self,
        snapshot: SnapshotSpec,
        containers: ContainerSet,
        snapshot_dir: Path,
    ) -> None:
        if not snapshot.files:
            return

        for key, content in snapshot.files.items():
            if key == "db:sql":
                sql_file = snapshot_dir / "_snapshot.sql"
                sql_file.write_text(content, encoding="utf-8")
                try:
                    await containers.cp("db", str(sql_file), "/tmp/_snapshot.sql")
                    await containers.exec("db", "mysql -u root -pr00tP@ss! < /tmp/_snapshot.sql")
                    await containers.exec("db", "rm -f /tmp/_snapshot.sql")
                finally:
                    sql_file.unlink(missing_ok=True)
                continue

            if ":" not in key:
                logger.warning("Skipping file with bad key format during validation: %s", key)
                continue

            host, path = key.split(":", 1)
            parent_dir = path.rsplit("/", 1)[0] if "/" in path else "/"
            await containers.exec(host, f"mkdir -p {shlex.quote(parent_dir)}")

            temp_file = snapshot_dir / f"_artifact_{host}_{abs(hash(key))}"
            temp_file.write_text(content, encoding="utf-8")
            try:
                await containers.cp(host, str(temp_file), path)
            finally:
                temp_file.unlink(missing_ok=True)

    @staticmethod
    def _validation_error(result: ValidationResult) -> str:
        failed = [check for check in result.checks if not check.passed]
        if not failed:
            return "unknown validation failure"
        payload = [
            {
                "name": check.name,
                "error": check.error,
                "details": check.details,
            }
            for check in failed
        ]
        return json.dumps(payload, sort_keys=True)

    def _snapshot_id(self, snapshot: SnapshotSpec) -> str:
        vuln_types = [v.type for v in snapshot.truth_graph.vulns]
        prefix = "snap_" + "_".join(vuln_types[:3]) if vuln_types else "snap_generated"
        return f"{prefix}_{int(time.time() * 1000)}"

    def _snapshot_dir(self, snapshot_id: str) -> Path:
        return self.store_dir / snapshot_id

    def _artifacts_dir(self, snapshot_id: str) -> Path:
        return self._snapshot_dir(snapshot_id) / "artifacts"

    def _materialize_snapshot(
        self,
        snapshot: SnapshotSpec,
        snapshot_id: str,
    ) -> SnapshotSpec:
        rendered = snapshot.model_copy(deep=True)

        topology = dict(rendered.topology)
        topology["snapshot_id"] = snapshot_id
        rendered.topology = topology

        snapshot_dir = self._snapshot_dir(snapshot_id)
        artifacts_dir = self._artifacts_dir(snapshot_id)
        if artifacts_dir.exists():
            shutil.rmtree(artifacts_dir)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        self.renderer.render(rendered, artifacts_dir)

        compose_path = artifacts_dir / "docker-compose.yml"
        rendered.compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
        return rendered
