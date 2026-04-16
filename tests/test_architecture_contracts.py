from __future__ import annotations

import ast
from pathlib import Path

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
    "build_config.py",
    "episode_config.py",
    "runtime_types.py",
    "snapshot.py",
    "world_ir.py",
    "resources.py",
    "service.py",
    "cli.py",
}

SHARED_ROOT_MODULES = {
    "build_config",
    "episode_config",
    "runtime_types",
    "snapshot",
    "world_ir",
    "resources",
    "service",
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
    allowed = REQUIRED_STAGE_PACKAGES | {
        path[:-3] for path in ALLOWED_ROOT_FILES if path.endswith(".py")
    }
    extras = [entry for entry in entries if entry not in allowed]

    assert not extras, (
        "top-level code entries still include architecture drift:\n" + "\n".join(extras)
    )


def test_stage_packages_do_not_import_stray_top_level_modules() -> None:
    allowed_import_targets = REQUIRED_STAGE_PACKAGES | SHARED_ROOT_MODULES
    failures: list[str] = []

    for package_name in sorted(REQUIRED_STAGE_PACKAGES):
        package_root = SRC_ROOT / package_name
        if not package_root.is_dir():
            failures.append(f"{package_name}: missing")
            continue

        imported_targets = _package_import_targets(package_root)
        stray_targets = sorted(imported_targets - allowed_import_targets)
        if stray_targets:
            failures.append(f"{package_name}: {', '.join(stray_targets)}")

    assert not failures, (
        "stage packages still import stray top-level modules instead of depending "
        "on stage packages or shared contracts only:\n" + "\n".join(failures)
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
