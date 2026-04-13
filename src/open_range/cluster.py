"""Kind-backed live backend for admitted snapshots."""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

from open_range.async_utils import run_async

logger = logging.getLogger(__name__)


def resolve_kubectl_cmd(kind_cluster: str = "openrange") -> tuple[str, ...]:
    """Return a usable kubectl command prefix."""
    if shutil.which("kubectl"):
        return ("kubectl",)
    return ("docker", "exec", f"{kind_cluster}-control-plane", "kubectl")


@dataclass(frozen=True, slots=True)
class ExecResult:
    """Structured result for a command run inside a live pod."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.exit_code == 0


@dataclass(slots=True)
class PodSet:
    """Handle to live pods for one admitted release."""

    project_name: str
    pod_ids: dict[str, str] = field(default_factory=dict)
    kubectl_cmd: tuple[str, ...] = ("kubectl",)

    async def exec(self, service: str, cmd: str, timeout: float = 30.0) -> ExecResult:
        namespace, pod = self._resolve(service)
        proc = await asyncio.create_subprocess_exec(
            *self.kubectl_cmd,
            "exec",
            pod,
            "-n",
            namespace,
            "--",
            "sh",
            "-c",
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ExecResult(
                stdout="", stderr="<timeout>", exit_code=124, timed_out=True
            )
        return ExecResult(
            stdout=(stdout or b"").decode(errors="replace"),
            stderr=(stderr or b"").decode(errors="replace"),
            exit_code=proc.returncode or 0,
        )

    async def is_healthy(self, service: str) -> bool:
        namespace, pod = self._resolve(service)
        proc = await asyncio.create_subprocess_exec(
            *self.kubectl_cmd,
            "get",
            "pod",
            pod,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.conditions[?(@.type=='Ready')].status}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return (stdout or b"").decode().strip() == "True"

    async def cp(self, service: str, src: str, dest: str) -> None:
        namespace, pod = self._resolve(service)
        proc = await asyncio.create_subprocess_exec(
            *self.kubectl_cmd,
            "cp",
            src,
            f"{namespace}/{pod}:{dest}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    async def restart(self, service: str, timeout: float = 30.0) -> None:
        namespace, pod = self._resolve(service)
        proc = await asyncio.create_subprocess_exec(
            *self.kubectl_cmd,
            "delete",
            "pod",
            pod,
            "-n",
            namespace,
            "--grace-period=5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()

    async def scale(
        self, service: str, replicas: int, timeout: float = 30.0
    ) -> ExecResult:
        namespace, _pod = self._resolve(service)
        proc = await asyncio.create_subprocess_exec(
            *self.kubectl_cmd,
            "scale",
            "deployment",
            service,
            "-n",
            namespace,
            f"--replicas={replicas}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ExecResult(
                stdout="", stderr="<timeout>", exit_code=124, timed_out=True
            )
        result = ExecResult(
            stdout=(stdout or b"").decode(errors="replace"),
            stderr=(stderr or b"").decode(errors="replace"),
            exit_code=proc.returncode or 0,
        )
        if not result.ok or replicas == 0:
            return result
        rollout = await asyncio.create_subprocess_exec(
            *self.kubectl_cmd,
            "rollout",
            "status",
            "deployment",
            service,
            "-n",
            namespace,
            f"--timeout={int(timeout)}s",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            rollout_stdout, rollout_stderr = await asyncio.wait_for(
                rollout.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            rollout.kill()
            return ExecResult(
                stdout=result.stdout,
                stderr=f"{result.stderr}\n<rollout-timeout>".strip(),
                exit_code=124,
                timed_out=True,
            )
        return ExecResult(
            stdout="\n".join(
                filter(
                    None,
                    [result.stdout, (rollout_stdout or b"").decode(errors="replace")],
                )
            ).strip(),
            stderr="\n".join(
                filter(
                    None,
                    [result.stderr, (rollout_stderr or b"").decode(errors="replace")],
                )
            ).strip(),
            exit_code=rollout.returncode or result.exit_code,
        )

    def _resolve(self, service: str) -> tuple[str, str]:
        entry = self._discover_current_ref(service)
        if entry:
            self.pod_ids[service] = entry
        elif service in self.pod_ids:
            entry = self.pod_ids[service]
        else:
            raise KeyError(f"no live pod mapping for service {service!r}")
        if "/" in entry:
            namespace, pod = entry.split("/", 1)
            return namespace, pod
        return self.project_name, entry

    def _discover_current_ref(self, service: str) -> str:
        proc = subprocess.run(
            [
                *self.kubectl_cmd,
                "get",
                "pods",
                "--all-namespaces",
                "-l",
                f"app.kubernetes.io/instance={self.project_name},openrange/service={service}",
                "-o",
                "jsonpath={range .items[0]}{.metadata.namespace}{'/'}{.metadata.name}{end}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.stdout.strip()


@dataclass(frozen=True, slots=True)
class BootedRelease:
    """Metadata for a booted Kind release."""

    release_name: str
    chart_dir: Path
    artifacts_dir: Path
    pods: PodSet


class LiveBackend(Protocol):
    def boot(self, *, snapshot_id: str, artifacts_dir: Path) -> BootedRelease: ...
    def teardown(self, release: BootedRelease) -> None: ...


class KindBackend:
    """Boot and tear down rendered charts on a Kind cluster."""

    def __init__(
        self,
        *,
        install_timeout_s: float = 300.0,
        uninstall_timeout_s: float = 120.0,
        health_timeout_s: float = 120.0,
        health_poll_interval_s: float = 2.0,
        kind_cluster: str = "openrange",
    ) -> None:
        self.install_timeout_s = install_timeout_s
        self.uninstall_timeout_s = uninstall_timeout_s
        self.health_timeout_s = health_timeout_s
        self.health_poll_interval_s = health_poll_interval_s
        self.kind_cluster = kind_cluster
        self.kubectl_cmd = resolve_kubectl_cmd(kind_cluster)

    def boot(self, *, snapshot_id: str, artifacts_dir: Path) -> BootedRelease:
        release_name = self.release_name_for(snapshot_id)
        chart_dir = artifacts_dir / "openrange"
        if not chart_dir.exists():
            chart_dir = artifacts_dir
        self.validate_runtime_env(artifacts_dir)
        self.prepare_images(chart_dir)
        self._helm_install(release_name, chart_dir)
        pod_map = self._discover_pods(release_name)
        if not pod_map:
            raise RuntimeError(
                f"installed release {release_name} but discovered no pods"
            )
        release = BootedRelease(
            release_name=release_name,
            chart_dir=chart_dir,
            artifacts_dir=artifacts_dir,
            pods=PodSet(
                project_name=release_name,
                pod_ids=pod_map,
                kubectl_cmd=self.kubectl_cmd,
            ),
        )
        self.wait_until_healthy(release, list(pod_map))
        return release

    def teardown(self, release: BootedRelease) -> None:
        self._run(
            ["helm", "uninstall", release.release_name, "--wait"],
            timeout=self.uninstall_timeout_s,
        )

    def wait_until_healthy(self, release: BootedRelease, services: list[str]) -> None:
        deadline = time.monotonic() + self.health_timeout_s
        pending = list(services)
        while pending and time.monotonic() < deadline:
            still_pending: list[str] = []
            for service in pending:
                try:
                    healthy = run_async(release.pods.is_healthy(service))
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
                "timed out waiting for healthy services: " + ", ".join(pending)
            )

    def prepare_images(self, chart_dir: Path) -> None:
        for image in self._chart_images(chart_dir):
            self._ensure_image_loaded(image)

    def validate_runtime_env(self, artifacts_dir: Path) -> None:
        chart_dir = artifacts_dir / "openrange"
        if not chart_dir.exists():
            chart_dir = artifacts_dir
        if self._chart_requires_cilium(chart_dir) and not self._cilium_ready():
            raise RuntimeError(
                "rendered chart requires Cilium, but the live cluster does not have "
                "a ready Cilium installation. Install Cilium first or render with "
                "the default Kubernetes network-policy backend."
            )

    @staticmethod
    def release_name_for(snapshot_id: str) -> str:
        safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in snapshot_id).strip(
            "-"
        )
        return f"or-{safe}"[:53]

    def _helm_install(self, release_name: str, chart_dir: Path) -> None:
        self._run(
            [
                "helm",
                "upgrade",
                "--install",
                release_name,
                str(chart_dir),
                "--set-string",
                f"global.namePrefix={release_name}",
                "--wait",
                "--timeout",
                f"{int(self.install_timeout_s)}s",
            ],
            timeout=self.install_timeout_s + 30.0,
        )

    def _discover_pods(self, release_name: str) -> dict[str, str]:
        result = self._run(
            [
                *self.kubectl_cmd,
                "get",
                "pods",
                "--all-namespaces",
                "-l",
                f"app.kubernetes.io/instance={release_name}",
                "-o",
                "jsonpath={range .items[*]}{.metadata.namespace}{'/'}{.metadata.name}{'|'}{.metadata.labels['openrange/service']}{'\\n'}{end}",
            ],
            timeout=30.0,
        )
        mapping: dict[str, str] = {}
        for line in result.stdout.splitlines():
            raw = line.strip()
            if not raw or "|" not in raw:
                continue
            pod_ref, service = raw.split("|", 1)
            if service:
                mapping[service] = pod_ref
        return mapping

    def _chart_images(self, chart_dir: Path) -> list[str]:
        values_path = chart_dir / "values.yaml"
        if not values_path.exists():
            return []
        values = yaml.safe_load(values_path.read_text(encoding="utf-8")) or {}
        images: list[str] = []

        def collect(section_name: str) -> None:
            section = values.get(section_name, {})
            if not isinstance(section, dict):
                return
            for raw in section.values():
                if not isinstance(raw, dict):
                    continue
                image = str(raw.get("image", "")).strip()
                if image and image not in images:
                    images.append(image)

        collect("services")
        collect("sandboxes")
        return images

    @staticmethod
    def _chart_requires_cilium(chart_dir: Path) -> bool:
        values_path = chart_dir / "values.yaml"
        if not values_path.exists():
            return False
        values = yaml.safe_load(values_path.read_text(encoding="utf-8")) or {}
        cilium = values.get("cilium", {})
        return isinstance(cilium, dict) and bool(cilium.get("enabled"))

    def _cilium_ready(self) -> bool:
        try:
            self._run(
                [
                    *self.kubectl_cmd,
                    "get",
                    "crd",
                    "ciliumnetworkpolicies.cilium.io",
                ],
                timeout=10.0,
            )
            daemonset = self._run(
                [
                    *self.kubectl_cmd,
                    "-n",
                    "kube-system",
                    "get",
                    "daemonset",
                    "cilium",
                    "-o",
                    "jsonpath={.status.numberReady}/{.status.desiredNumberScheduled}",
                ],
                timeout=10.0,
            )
        except RuntimeError:
            return False

        status = daemonset.stdout.strip()
        if "/" not in status:
            return False
        ready, desired = status.split("/", 1)
        return desired != "0" and ready == desired

    def _ensure_image_loaded(self, image: str) -> None:
        if not image:
            return
        if not self._docker_image_present(image):
            self._run(
                ["docker", "pull", image], timeout=max(self.install_timeout_s, 300.0)
            )
        self._run(
            ["kind", "load", "docker-image", image, "--name", self.kind_cluster],
            timeout=max(self.install_timeout_s, 300.0),
        )

    @staticmethod
    def _docker_image_present(image: str) -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0

    @staticmethod
    def _run(
        args: list[str] | tuple[str, ...], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown failure"
            raise RuntimeError(
                f"{' '.join(args)} failed with exit code {result.returncode}: {detail}"
            )
        return result
