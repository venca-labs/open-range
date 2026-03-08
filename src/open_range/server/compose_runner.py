"""Helpers for booting rendered snapshot bundles as temporary compose projects."""

from __future__ import annotations

import json
import shlex
import time
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from open_range.protocols import ContainerSet

PAYLOAD_MANIFEST_NAME = "file-payloads.json"


@dataclass(frozen=True, slots=True)
class BootedSnapshotProject:
    """Booted compose project metadata for a rendered child snapshot."""

    project_name: str
    compose_file: Path
    artifacts_dir: Path
    containers: ContainerSet


class ComposeProjectRunner:
    """Boot and tear down rendered snapshot bundles via ``docker compose``."""

    def __init__(
        self,
        *,
        build_timeout_s: float = 300.0,
        up_timeout_s: float = 300.0,
        down_timeout_s: float = 120.0,
        health_timeout_s: float = 120.0,
        health_poll_interval_s: float = 2.0,
        remove_volumes: bool = True,
    ) -> None:
        self.build_timeout_s = build_timeout_s
        self.up_timeout_s = up_timeout_s
        self.down_timeout_s = down_timeout_s
        self.health_timeout_s = health_timeout_s
        self.health_poll_interval_s = health_poll_interval_s
        self.remove_volumes = remove_volumes

    def boot(
        self,
        *,
        snapshot_id: str,
        artifacts_dir: Path,
        compose: dict[str, Any],
        project_name: str | None = None,
    ) -> BootedSnapshotProject:
        compose_file = artifacts_dir / "docker-compose.yml"
        project_name = project_name or self.project_name_for(snapshot_id)

        self._run(
            [
                "docker",
                "compose",
                "-p",
                project_name,
                "-f",
                str(compose_file),
                "build",
            ],
            cwd=artifacts_dir,
            timeout=self.build_timeout_s,
        )
        self._run(
            [
                "docker",
                "compose",
                "-p",
                project_name,
                "-f",
                str(compose_file),
                "up",
                "-d",
            ],
            cwd=artifacts_dir,
            timeout=self.up_timeout_s,
        )

        services = list((compose or {}).get("services", {}).keys())
        container_ids: dict[str, str] = {}
        for service in services:
            result = self._run(
                [
                    "docker",
                    "compose",
                    "-p",
                    project_name,
                    "-f",
                    str(compose_file),
                    "ps",
                    "-q",
                    service,
                ],
                cwd=artifacts_dir,
                timeout=30.0,
            )
            container_id = result.stdout.strip()
            if container_id:
                container_ids[service] = container_id

        project = BootedSnapshotProject(
            project_name=project_name,
            compose_file=compose_file,
            artifacts_dir=artifacts_dir,
            containers=ContainerSet(
                project_name=project_name,
                container_ids=container_ids,
            ),
        )
        try:
            self._wait_until_healthy(project, services)
        except Exception:
            self.teardown(project)
            raise
        return project

    def teardown(self, project: BootedSnapshotProject) -> None:
        args = [
            "docker",
            "compose",
            "-p",
            project.project_name,
            "-f",
            str(project.compose_file),
            "down",
        ]
        if self.remove_volumes:
            args.append("-v")
        self._run(
            args,
            cwd=project.artifacts_dir,
            timeout=self.down_timeout_s,
        )

    @staticmethod
    def project_name_for(snapshot_id: str) -> str:
        safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in snapshot_id).strip("-")
        return f"openrange-{safe}"[:63]

    def _wait_until_healthy(
        self,
        project: BootedSnapshotProject,
        services: list[str],
    ) -> None:
        deadline = time.monotonic() + self.health_timeout_s
        pending = list(services)
        while pending and time.monotonic() < deadline:
            still_pending: list[str] = []
            for service in pending:
                try:
                    healthy = _run_async(project.containers.is_healthy(service))
                except Exception:
                    healthy = False
                if not healthy:
                    still_pending.append(service)
            if not still_pending:
                return
            pending = still_pending
            time.sleep(self.health_poll_interval_s)
        if pending:
            raise RuntimeError(
                "Timed out waiting for healthy services: "
                + ", ".join(pending)
            )

    @staticmethod
    def _run(
        args: list[str],
        *,
        cwd: Path,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            detail = stderr or stdout or "unknown docker compose failure"
            raise RuntimeError(
                f"{' '.join(args)} failed with exit code {result.returncode}: {detail}"
            )
        return result


def apply_rendered_payloads(
    *,
    containers: ContainerSet,
    artifacts_dir: Path,
    compose: dict[str, Any],
) -> None:
    """Copy rendered payload artifacts into a booted compose project."""
    manifest_path = artifacts_dir / PAYLOAD_MANIFEST_NAME
    if not manifest_path.exists():
        return

    payloads = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payloads, dict):
        raise ValueError(f"{manifest_path} must contain a JSON object")

    for file_key, rel_path in payloads.items():
        src = artifacts_dir / str(rel_path)
        if not src.exists():
            raise FileNotFoundError(f"Rendered payload missing for {file_key}: {src}")

        if file_key == "db:sql":
            _apply_sql_payload(containers, src, compose)
            continue

        if ":" not in file_key:
            continue

        container, target_path = file_key.split(":", 1)
        parent_dir = PurePosixPath(target_path).parent.as_posix() or "/"
        _run_async(containers.exec(container, f"mkdir -p {shlex.quote(parent_dir)}"))
        _run_async(containers.cp(container, str(src), target_path))


def _apply_sql_payload(
    containers: ContainerSet,
    sql_path: Path,
    compose: dict[str, Any],
) -> None:
    root_password = _mysql_root_password(compose)
    _run_async(containers.cp("db", str(sql_path), "/tmp/openrange-generated.sql"))
    _run_async(
        containers.exec(
            "db",
            f"mysql -u root -p{shlex.quote(root_password)} < /tmp/openrange-generated.sql",
        )
    )
    _run_async(containers.exec("db", "rm -f /tmp/openrange-generated.sql"))


def _mysql_root_password(compose: dict[str, Any]) -> str:
    db_service = compose.get("services", {}).get("db", {})
    if not isinstance(db_service, dict):
        return "r00tP@ss!"

    environment = db_service.get("environment", {})
    if isinstance(environment, dict):
        return str(environment.get("MYSQL_ROOT_PASSWORD", "r00tP@ss!"))
    if isinstance(environment, list):
        for item in environment:
            text = str(item)
            if text.startswith("MYSQL_ROOT_PASSWORD="):
                return text.split("=", 1)[1]
    return "r00tP@ss!"


def _run_async(coro):
    import asyncio

    return asyncio.run(coro)
