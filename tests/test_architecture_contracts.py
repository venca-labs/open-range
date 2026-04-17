from __future__ import annotations

import ast
from pathlib import Path

import open_range

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src" / "open_range"

# This target is the clean package shape we explicitly want:
# - tiny root with shared/public contracts only
# - real stage packages named after the actual flow
# - no wrapper/noise packages
# - no one-file package theater for the major subsystems
# - stage packages depend on other stage packages or shared root contracts only

ALLOWED_ROOT_FILES = {
    "__init__.py",
    "cli.py",
}

SHARED_SUPPORT_PACKAGES = {
    "agents",
    "builder",
    "config",
    "contracts",
    "dashboard",
    "sdk",
    "support",
}

REQUIRED_STAGE_PACKAGES = {
    "manifest",
    "compiler",
    "weaknesses",
    "objectives",
    "synth",
    "render",
    "admission",
    "store",
    "runtime",
    "training",
    "catalog",
}

DISALLOWED_TOP_LEVEL_PACKAGES = {
    "admit",
    "audit",
    "code_web",
    "curriculum",
    "execution",
    "pipeline",
    "predicates",
    "tracegen",
    "weakness_families",
}

MULTI_MODULE_STAGE_PACKAGES = {
    "admission",
    "compiler",
    "manifest",
    "runtime",
    "training",
    "catalog",
    "weaknesses",
    "objectives",
    "synth",
}

NON_ARCHITECTURE_DIRS = {
    "__pycache__",
    "_resources",
    "chart",
    "devtools",
    "templates",
}

TOP_LEVEL_PACKAGE_NAMES = REQUIRED_STAGE_PACKAGES | SHARED_SUPPORT_PACKAGES

ALLOWED_STAGE_IMPORTS = {
    "manifest": {"catalog", "objectives"},
    "compiler": {"catalog", "config", "contracts", "manifest", "objectives"},
    "weaknesses": {"catalog", "contracts", "manifest", "objectives"},
    "objectives": {"catalog", "contracts", "support"},
    "synth": {"contracts", "weaknesses"},
    "render": {"contracts", "support", "synth"},
    "admission": {
        "catalog",
        "config",
        "contracts",
        "objectives",
        "render",
        "runtime",
        "support",
        "weaknesses",
    },
    "store": {
        "admission",
        "compiler",
        "config",
        "contracts",
        "manifest",
        "render",
        "synth",
        "weaknesses",
    },
    "runtime": {
        "agents",
        "builder",
        "catalog",
        "config",
        "contracts",
        "objectives",
        "render",
        "support",
        "weaknesses",
    },
    "training": {
        "catalog",
        "config",
        "contracts",
        "objectives",
        "runtime",
        "store",
        "support",
        "weaknesses",
    },
    "catalog": {"contracts", "objectives"},
}

ALLOWED_SUPPORT_IMPORTS = {
    "agents": {"config", "contracts", "runtime"},
    "builder": {"contracts"},
    "config": {"manifest"},
    "contracts": {"catalog", "manifest"},
    "dashboard": {"config", "contracts", "render", "runtime", "sdk", "store"},
    "support": {"contracts"},
    "sdk": {"config", "contracts", "render", "runtime", "store"},
}

FORBIDDEN_ENTRYPOINT_IMPORT_MODULES = {
    "importlib",
    "pkg_resources",
    "pkgutil",
}

FORBIDDEN_ENTRYPOINT_CALL_NAMES = {
    "__import__",
    "entry_points",
    "import_module",
    "iter_modules",
    "walk_packages",
}


def test_root_file_surface_matches_target() -> None:
    root_files = {
        path.name for path in SRC_ROOT.glob("*.py") if not path.name.startswith("_")
    }
    extras = sorted(root_files - ALLOWED_ROOT_FILES)

    assert len(root_files) <= 10, (
        "root file surface is still too large; it should stay under 10 entry files, "
        f"but found {len(root_files)}:\n" + "\n".join(sorted(root_files))
    )
    assert not extras, (
        "root file surface is still larger than the target architecture allows:\n"
        + "\n".join(extras)
    )


def test_root_package_exports_small_guided_surface() -> None:
    required_exports = {
        "BuildConfig",
        "BuildPipeline",
        "DEFAULT_BUILD_CONFIG",
        "DEFAULT_EPISODE_CONFIG",
        "EnterpriseSaaSManifest",
        "EpisodeConfig",
        "OFFLINE_BUILD_CONFIG",
        "OFFLINE_REFERENCE_BUILD_CONFIG",
        "OpenRange",
        "Snapshot",
        "WorldIR",
        "load_bundled_manifest",
        "manifest_schema",
        "validate_manifest",
        "world_hash",
    }
    exported = set(open_range.__all__)
    assert required_exports <= exported
    assert len(exported) <= len(required_exports) + 2


def test_root_private_helpers_are_gone() -> None:
    private_helpers = sorted(
        path.name for path in SRC_ROOT.glob("_*.py") if path.name != "__init__.py"
    )

    assert not private_helpers, (
        "root still contains private helper modules that should live under a stage "
        "package instead:\n" + "\n".join(private_helpers)
    )


def test_required_stage_packages_exist() -> None:
    missing = sorted(
        package_name
        for package_name in REQUIRED_STAGE_PACKAGES
        if not (SRC_ROOT / package_name).is_dir()
    )

    assert not missing, "required stage packages are missing:\n" + "\n".join(missing)


def test_wrapper_and_noise_packages_are_gone() -> None:
    present = sorted(
        package_name
        for package_name in DISALLOWED_TOP_LEVEL_PACKAGES
        if (SRC_ROOT / package_name).is_dir()
    )

    assert not present, (
        "wrapper/noise packages still exist at the top level:\n" + "\n".join(present)
    )


def test_major_stage_packages_are_not_single_file_wrappers() -> None:
    failures: list[str] = []

    for package_name in sorted(MULTI_MODULE_STAGE_PACKAGES):
        package_root = SRC_ROOT / package_name
        if not package_root.is_dir():
            failures.append(f"{package_name}: missing")
            continue
        module_count = _python_module_count(package_root)
        if module_count <= 1:
            failures.append(f"{package_name}: only {module_count} python module")

    assert not failures, (
        "major stage packages are still shallow wrapper packages:\n"
        + "\n".join(failures)
    )


def test_top_level_entries_stay_small_and_stage_shaped() -> None:
    entries = sorted(_top_level_code_entries())
    allowed = (
        REQUIRED_STAGE_PACKAGES
        | SHARED_SUPPORT_PACKAGES
        | {path[:-3] for path in ALLOWED_ROOT_FILES if path.endswith(".py")}
    )
    extras = [entry for entry in entries if entry not in allowed]

    assert not extras, (
        "top-level code entries still include architecture drift:\n" + "\n".join(extras)
    )


def test_stage_packages_follow_dependency_matrix() -> None:
    failures: list[str] = []

    for package_name, allowed_targets in sorted(ALLOWED_STAGE_IMPORTS.items()):
        unexpected_targets = _unexpected_top_level_imports(
            SRC_ROOT / package_name,
            allowed_targets,
        )
        if unexpected_targets:
            failures.append(f"{package_name}: {', '.join(unexpected_targets)}")

    assert not failures, (
        "stage packages still import across boundaries that do not match the "
        "documented stage story:\n" + "\n".join(failures)
    )


def test_support_packages_follow_dependency_matrix() -> None:
    failures: list[str] = []

    for package_name, allowed_targets in sorted(ALLOWED_SUPPORT_IMPORTS.items()):
        unexpected_targets = _unexpected_top_level_imports(
            SRC_ROOT / package_name,
            allowed_targets,
        )
        if unexpected_targets:
            failures.append(f"{package_name}: {', '.join(unexpected_targets)}")

    assert not failures, (
        "support packages still reach into stage code in ways that blur package "
        "ownership:\n" + "\n".join(failures)
    )


def test_contracts_package_does_not_import_render_or_admission() -> None:
    imported_targets = _package_import_targets(SRC_ROOT / "contracts")
    forbidden = sorted(imported_targets & {"admission", "render"})

    assert not forbidden, (
        "contracts still depends on stage packages that should depend on contracts "
        "instead:\n" + "\n".join(forbidden)
    )


def test_package_entrypoints_do_not_hide_import_bootstrap_hacks() -> None:
    failures: list[str] = []

    for entrypoint_path in sorted(_package_entrypoint_paths()):
        violations = _entrypoint_hack_violations(entrypoint_path)
        if violations:
            package_name = _package_name_for_entrypoint(entrypoint_path)
            failures.append(f"{package_name}: {', '.join(violations)}")

    assert not failures, (
        "package entrypoints still contain lazy import glue or side-effectful "
        "bootstrap code:\n" + "\n".join(failures)
    )


def _top_level_code_entries() -> set[str]:
    entries: set[str] = set()

    for path in SRC_ROOT.iterdir():
        if path.name in NON_ARCHITECTURE_DIRS:
            continue
        if path.is_file() and path.suffix == ".py":
            if path.name.startswith("_"):
                continue
            entries.add(path.stem)
        elif path.is_dir():
            if any(child.suffix == ".py" for child in path.rglob("*.py")):
                entries.add(path.name)

    return entries


def _python_module_count(package_root: Path) -> int:
    return sum(
        1 for path in package_root.rglob("*.py") if "__pycache__" not in path.parts
    )


def _package_import_targets(package_root: Path) -> set[str]:
    targets: set[str] = set()

    for module_path in package_root.rglob("*.py"):
        if "__pycache__" in module_path.parts:
            continue
        tree = ast.parse(module_path.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_level = _top_level_target_from_import(alias.name)
                    if top_level is not None:
                        targets.add(top_level)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                top_levels = _top_level_targets_from_from_import(
                    node.module, node.names
                )
                targets.update(top_levels)

    return targets


def _unexpected_top_level_imports(
    package_root: Path, allowed_targets: set[str]
) -> list[str]:
    package_name = package_root.name
    imported_targets = _package_import_targets(package_root) & TOP_LEVEL_PACKAGE_NAMES
    unexpected_targets = sorted(imported_targets - allowed_targets - {package_name})
    return unexpected_targets


def _package_entrypoint_paths() -> tuple[Path, ...]:
    package_names = REQUIRED_STAGE_PACKAGES | SHARED_SUPPORT_PACKAGES
    return tuple(
        [SRC_ROOT / "__init__.py"]
        + [
            SRC_ROOT / package_name / "__init__.py"
            for package_name in sorted(package_names)
            if (SRC_ROOT / package_name / "__init__.py").exists()
        ]
    )


def _package_name_for_entrypoint(entrypoint_path: Path) -> str:
    if entrypoint_path.parent == SRC_ROOT:
        return "open_range"
    return entrypoint_path.parent.name


def _entrypoint_hack_violations(entrypoint_path: Path) -> list[str]:
    tree = ast.parse(entrypoint_path.read_text(encoding="utf-8"))
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {
            "__getattr__",
            "__dir__",
        }:
            violations.append(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_ENTRYPOINT_IMPORT_MODULES:
                    violations.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module_name = (node.module or "").split(".")[0]
            if module_name in FORBIDDEN_ENTRYPOINT_IMPORT_MODULES:
                violations.append(f"from {node.module} import ...")

    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                continue
        if _statement_contains_forbidden_call(node):
            violations.append("top-level dynamic import/bootstrap call")

    return sorted(set(violations))


def _statement_contains_forbidden_call(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        call_name = _call_name(child.func)
        if call_name in FORBIDDEN_ENTRYPOINT_CALL_NAMES:
            return True
    return False


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST | None = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _top_level_target_from_import(module_name: str) -> str | None:
    parts = module_name.split(".")
    if not parts or parts[0] != "open_range":
        return None
    if len(parts) == 1:
        return None
    return parts[1]


def _top_level_targets_from_from_import(
    module_name: str | None, names: list[ast.alias]
) -> set[str]:
    if module_name is None:
        return set()

    module_parts = module_name.split(".")
    if not module_parts or module_parts[0] != "open_range":
        return set()

    if len(module_parts) > 1:
        return {module_parts[1]}

    targets: set[str] = set()
    for alias in names:
        if alias.name == "*":
            continue
        targets.add(alias.name.split(".")[0])
    return targets
