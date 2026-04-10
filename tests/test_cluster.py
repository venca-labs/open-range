from __future__ import annotations

from subprocess import CompletedProcess

import open_range.cluster as cluster_mod
from open_range.async_utils import run_async
from open_range.cluster import KindBackend, PodSet


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
