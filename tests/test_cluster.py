from __future__ import annotations

from open_range.async_utils import run_async
from open_range.cluster import PodSet
import open_range.cluster as cluster_mod


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

    podset = PodSet(project_name="or-demo", pod_ids={"svc-web": "ns/svc-web-pod"})
    monkeypatch.setattr(PodSet, "_discover_current_ref", lambda self, service: "")
    monkeypatch.setattr(
        cluster_mod.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    assert run_async(podset.is_healthy("svc-web")) is True


def test_podset_resolve_caches_discovered_refs(monkeypatch) -> None:
    podset = PodSet(project_name="or-demo")
    monkeypatch.setattr(
        PodSet, "_discover_current_ref", lambda self, service: "ns/svc-web-pod"
    )

    assert podset._resolve("svc-web") == ("ns", "svc-web-pod")
    assert podset.pod_ids["svc-web"] == "ns/svc-web-pod"
