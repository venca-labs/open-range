from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess

import pytest

import open_range.cluster as cluster_mod
import open_range.k3d_runner as k3d_mod
from open_range.async_utils import run_async
from open_range.cluster import KindBackend, PodSet, resolve_host_binary
from open_range.k3d_runner import K3dBackend


class _FakeProc:
    def __init__(self, stdout: bytes = b"True", stderr: bytes = b"") -> None:
        self.returncode = 0
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


def test_podset_is_healthy_uses_async_kubectl(monkeypatch) -> None:
    async def fake_create_subprocess_exec(*args, **kwargs):
        del args, kwargs
        return _FakeProc()

    podset = PodSet(project_name="or-test", pod_ids={"svc-web": "ns/svc-web-pod"})
    monkeypatch.setattr(PodSet, "_discover_current_ref", lambda self, service: "")
    monkeypatch.setattr(
        cluster_mod.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    assert run_async(podset.is_healthy("svc-web")) is True


def test_podset_resolve_caches_discovered_refs(monkeypatch) -> None:
    podset = PodSet(project_name="or-test")
    monkeypatch.setattr(
        PodSet, "_discover_current_ref", lambda self, service: "ns/svc-web-pod"
    )

    assert podset._resolve("svc-web") == ("ns", "svc-web-pod")
    assert podset.pod_ids["svc-web"] == "ns/svc-web-pod"


def test_kind_backend_discovers_pods_from_service_label(monkeypatch) -> None:
    captured: dict[str, object] = {}
    backend = KindBackend()

    def fake_run(args, *, timeout):
        captured["args"] = tuple(args)
        captured["timeout"] = timeout
        return CompletedProcess(
            list(args),
            0,
            stdout="ns/svc-web-pod|svc-web\nns/sandbox-red-pod|sandbox-red\n",
            stderr="",
        )

    monkeypatch.setattr(KindBackend, "_run", staticmethod(fake_run))

    assert backend._discover_pods("or-test") == {
        "svc-web": "ns/svc-web-pod",
        "sandbox-red": "ns/sandbox-red-pod",
    }
    assert "labels['openrange/service']" in captured["args"][-1]
    assert captured["timeout"] == 30.0


def test_resolve_host_binary_finds_common_local_bin(
    tmp_path: Path, monkeypatch
) -> None:
    local_bin = tmp_path / ".local" / "bin"
    local_bin.mkdir(parents=True)
    binary = local_bin / "helm"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(cluster_mod.shutil, "which", lambda name: None)
    monkeypatch.setattr(cluster_mod, "_COMMON_BINARY_DIRS", (str(local_bin),))

    assert resolve_host_binary("helm") == str(binary)


def test_kind_backend_uses_resolved_host_binaries(monkeypatch) -> None:
    paths = {
        "helm": "/home/ghost/.local/bin/helm",
        "kind": "/home/ghost/.local/bin/kind",
        "docker": "/usr/bin/docker",
        "kubectl": "/home/ghost/.local/bin/kubectl",
    }
    monkeypatch.setattr(
        cluster_mod, "resolve_host_binary", lambda name: paths.get(name)
    )

    backend = KindBackend(kind_cluster="openrange")

    assert backend.helm_bin == paths["helm"]
    assert backend.kind_bin == paths["kind"]
    assert backend.docker_bin == paths["docker"]
    assert backend.kubectl_cmd == (paths["kubectl"],)


def test_kind_backend_requires_cilium_when_chart_requests_it(
    tmp_path: Path, monkeypatch
) -> None:
    chart_dir = tmp_path / "openrange"
    chart_dir.mkdir()
    (chart_dir / "values.yaml").write_text(
        "cilium:\n  enabled: true\n", encoding="utf-8"
    )

    backend = KindBackend()
    monkeypatch.setattr(KindBackend, "_cilium_ready", lambda self: False)

    with pytest.raises(RuntimeError, match="requires Cilium"):
        backend.validate_runtime_env(tmp_path)


def test_kind_backend_boot_validates_runtime_env_before_install(
    tmp_path: Path, monkeypatch
) -> None:
    chart_dir = tmp_path / "openrange"
    chart_dir.mkdir()
    calls: list[tuple[str, object]] = []
    backend = KindBackend()

    monkeypatch.setattr(
        KindBackend,
        "validate_runtime_env",
        lambda self, artifacts_dir: calls.append(("validate", artifacts_dir)),
    )
    monkeypatch.setattr(
        KindBackend,
        "prepare_images",
        lambda self, live_chart_dir: calls.append(("prepare", live_chart_dir)),
    )
    monkeypatch.setattr(
        KindBackend,
        "_helm_install",
        lambda self, release_name, live_chart_dir: calls.append(
            ("helm", (release_name, live_chart_dir))
        ),
    )
    monkeypatch.setattr(
        KindBackend,
        "_discover_pods",
        lambda self, release_name: {"svc-web": "ns/svc-web-pod"},
    )
    monkeypatch.setattr(
        KindBackend,
        "wait_until_healthy",
        lambda self, release, services: calls.append(("wait", tuple(services))),
    )

    backend.boot(snapshot_id="demo", artifacts_dir=tmp_path)

    assert calls[0] == ("validate", tmp_path)
    assert calls[1] == ("prepare", chart_dir)


def test_kind_backend_retries_after_stale_failed_helm_release(
    tmp_path: Path, monkeypatch
) -> None:
    chart_dir = tmp_path / "openrange"
    chart_dir.mkdir()
    calls: list[tuple[str, ...]] = []
    backend = KindBackend()

    def fake_run(args, *, timeout):
        del timeout
        call = tuple(args)
        calls.append(call)
        if (
            call[:4] == (backend.helm_bin, "upgrade", "--install", "or-demo")
            and len(
                [
                    item
                    for item in calls
                    if item[:4] == (backend.helm_bin, "upgrade", "--install", "or-demo")
                ]
            )
            == 1
        ):
            raise RuntimeError(
                "helm upgrade --install or-demo failed with exit code 1: Error: "
                'UPGRADE FAILED: "or-demo" has no deployed releases'
            )
        return CompletedProcess(list(args), 0, stdout="", stderr="")

    monkeypatch.setattr(KindBackend, "_run", staticmethod(fake_run))

    backend._helm_install("or-demo", chart_dir)

    assert calls == [
        (
            backend.helm_bin,
            "upgrade",
            "--install",
            "or-demo",
            str(chart_dir),
            "--set-string",
            "global.namePrefix=or-demo",
            "--wait",
            "--timeout",
            "300s",
        ),
        (backend.helm_bin, "uninstall", "or-demo"),
        (
            backend.helm_bin,
            "upgrade",
            "--install",
            "or-demo",
            str(chart_dir),
            "--set-string",
            "global.namePrefix=or-demo",
            "--wait",
            "--timeout",
            "300s",
        ),
    ]


def test_kind_backend_repuls_image_when_local_arch_mismatches(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []
    backend = KindBackend(kind_cluster="openrange")
    monkeypatch.setattr(
        KindBackend, "_host_architecture", staticmethod(lambda: "arm64")
    )
    monkeypatch.setattr(
        KindBackend,
        "_docker_image_architecture",
        classmethod(lambda cls, image: "amd64"),
    )
    monkeypatch.setattr(
        KindBackend,
        "_run",
        staticmethod(
            lambda args, *, timeout: (
                calls.append(tuple(args))
                or CompletedProcess(list(args), 0, stdout="", stderr="")
            )
        ),
    )

    backend._ensure_image_loaded("mysql:8.0")

    assert calls[0] == (
        backend.docker_bin,
        "pull",
        "--platform",
        "linux/arm64",
        "mysql:8.0",
    )
    assert calls[1] == (
        backend.kind_bin,
        "load",
        "docker-image",
        "mysql:8.0",
        "--name",
        "openrange",
    )


def test_kind_backend_teardown_is_best_effort(monkeypatch) -> None:
    calls: list[tuple[tuple[str, ...], float]] = []
    backend = KindBackend(kind_cluster="openrange")

    def fake_run(args, *, timeout):
        calls.append((tuple(args), timeout))
        raise RuntimeError("release not found")

    monkeypatch.setattr(KindBackend, "_run", staticmethod(fake_run))

    backend.teardown(
        cluster_mod.BootedRelease(
            release_name="or-demo",
            chart_dir=Path("/tmp/chart"),
            artifacts_dir=Path("/tmp/artifacts"),
            pods=cluster_mod.PodSet(project_name="or-demo"),
        )
    )

    assert calls == [((backend.helm_bin, "uninstall", "or-demo"), 30.0)]


def test_kind_backend_skips_repull_when_local_arch_matches(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []
    backend = KindBackend(kind_cluster="openrange")
    monkeypatch.setattr(
        KindBackend, "_host_architecture", staticmethod(lambda: "arm64")
    )
    monkeypatch.setattr(
        KindBackend,
        "_docker_image_architecture",
        classmethod(lambda cls, image: "arm64"),
    )
    monkeypatch.setattr(
        KindBackend,
        "_run",
        staticmethod(
            lambda args, *, timeout: (
                calls.append(tuple(args))
                or CompletedProcess(list(args), 0, stdout="", stderr="")
            )
        ),
    )

    backend._ensure_image_loaded("mysql:8.0")

    assert calls == [
        (
            backend.kind_bin,
            "load",
            "docker-image",
            "mysql:8.0",
            "--name",
            "openrange",
        )
    ]


def test_k3d_backend_requires_ready_cilium_even_without_cilium_chart(
    tmp_path: Path, monkeypatch
) -> None:
    chart_dir = tmp_path / "openrange"
    chart_dir.mkdir()
    (chart_dir / "values.yaml").write_text("services: {}\n", encoding="utf-8")

    backend = K3dBackend()
    monkeypatch.setattr(K3dBackend, "_cilium_ready", lambda self: False)

    with pytest.raises(RuntimeError, match="requires Cilium"):
        backend.validate_runtime_env(tmp_path)


def test_k3d_backend_uses_k3d_context_when_kubectl_is_available(monkeypatch) -> None:
    monkeypatch.setattr(
        k3d_mod,
        "resolve_host_binary",
        lambda name: "/usr/bin/kubectl" if name == "kubectl" else "/usr/bin/docker",
    )

    backend = K3dBackend(kind_cluster="openrange")

    assert backend.kubectl_cmd == ("/usr/bin/kubectl", "--context", "k3d-openrange")


def test_k3d_backend_repuls_image_when_local_arch_mismatches(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []
    backend = K3dBackend(kind_cluster="openrange")
    monkeypatch.setattr(K3dBackend, "_host_architecture", staticmethod(lambda: "arm64"))
    monkeypatch.setattr(
        K3dBackend,
        "_docker_image_architecture",
        classmethod(lambda cls, image: "amd64"),
    )
    monkeypatch.setattr(
        K3dBackend,
        "_run",
        staticmethod(
            lambda args, *, timeout: (
                calls.append(tuple(args))
                or CompletedProcess(list(args), 0, stdout="", stderr="")
            )
        ),
    )

    backend._ensure_image_loaded("mysql:8.0")

    assert calls[0] == (
        "docker",
        "pull",
        "--platform",
        "linux/arm64",
        "mysql:8.0",
    )
