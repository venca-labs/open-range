from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess

import pytest

import open_range.render.live as cluster_mod
import open_range.render.live_k3d as k3d_mod
from open_range.render.live import KindBackend, PodSet
from open_range.render.live_k3d import K3dBackend
from open_range.support.async_utils import run_async


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


def test_kind_backend_teardown_deletes_release_namespaces(
    tmp_path: Path, monkeypatch
) -> None:
    chart_dir = tmp_path / "openrange"
    chart_dir.mkdir()
    (chart_dir / "values.yaml").write_text(
        "zones:\n  external: {}\n  internal: {}\n", encoding="utf-8"
    )
    backend = KindBackend(uninstall_timeout_s=45.0)
    calls: list[tuple[tuple[str, ...], float]] = []

    def fake_run(args, *, timeout):
        calls.append((tuple(args), timeout))
        return CompletedProcess(list(args), 0, stdout="", stderr="")

    monkeypatch.setattr(KindBackend, "_run", staticmethod(fake_run))

    release = cluster_mod.BootedRelease(
        release_name="or-demo",
        chart_dir=chart_dir,
        artifacts_dir=tmp_path,
        pods=PodSet(project_name="or-demo"),
    )
    backend.teardown(release)

    assert calls[0][0][:2] == (backend.helm_bin, "uninstall")
    kubectl_len = len(backend.kubectl_cmd)
    assert calls[1][0][: kubectl_len + 2] == (
        *backend.kubectl_cmd,
        "delete",
        "namespace",
    )
    assert calls[1][0][kubectl_len + 2 : kubectl_len + 4] == (
        "or-demo-external",
        "or-demo-internal",
    )
    assert "--ignore-not-found=true" in calls[1][0]
    assert "--wait=true" in calls[1][0]
    assert "--timeout=45s" in calls[1][0]


def test_namespace_template_runs_as_pre_install_hook() -> None:
    template_path = (
        Path(cluster_mod.__file__).resolve().parent.parent
        / "chart"
        / "templates"
        / "namespaces.yaml"
    )
    content = template_path.read_text(encoding="utf-8")

    assert '"helm.sh/hook": pre-install' in content
    assert '"helm.sh/hook-weight": "-100"' in content


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
    monkeypatch.setattr(k3d_mod.shutil, "which", lambda name: "/usr/bin/kubectl")

    backend = K3dBackend(kind_cluster="openrange")

    assert backend.kubectl_cmd == ("kubectl", "--context", "k3d-openrange")
