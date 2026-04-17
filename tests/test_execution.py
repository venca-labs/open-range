from __future__ import annotations

import shlex
from types import SimpleNamespace

import pytest

from open_range.cluster import ExecResult
from open_range.execution import PodActionBackend, _http_fetch_command
from open_range.runtime_types import Action, IntegritySample
from open_range.world_ir import ServiceSpec


def test_mail_command_quotes_smtp_payload_and_target() -> None:
    backend = PodActionBackend()
    backend._service_by_id = {
        "svc-email": ServiceSpec(
            id="svc-email",
            kind="email",
            host="mail-1",
            ports=(25,),
            dependencies=(),
            telemetry_surfaces=(),
        )
    }
    action = Action(
        actor_id="red",
        role="red",
        kind="mail",
        payload={
            "target": "svc-email",
            "from": "attacker\n; rm -rf /",
            "to": "victim@corp.local",
            "subject": "hi'; touch /tmp/pwned #",
        },
    )

    payload = (
        "HELO corp.local\n"
        "MAIL FROM:<attacker\n; rm -rf />\n"
        "RCPT TO:<victim@corp.local>\n"
        "DATA\n"
        "Subject: hi'; touch /tmp/pwned #\n\n"
        "OpenRange test mail.\n"
        ".\n"
        "QUIT\n"
    )

    command = backend._mail_command(action)

    assert (
        command
        == f"printf %s {shlex.quote(payload)} | nc -w 3 {shlex.quote('svc-email')} 25"
    )


def test_execution_helpers_raise_clear_errors_when_unbound() -> None:
    backend = PodActionBackend()

    with pytest.raises(RuntimeError, match="no live release is bound"):
        backend._is_contained("svc-web")
    with pytest.raises(RuntimeError, match="no active snapshot is bound"):
        backend._weakness_for("svc-web")


def test_runner_for_red_service_origin_uses_zone_tooling_runner() -> None:
    backend = PodActionBackend()
    backend._service_by_id = {
        "svc-web": ServiceSpec(
            id="svc-web",
            kind="web_app",
            host="web-1",
            ports=(80,),
            dependencies=(),
            telemetry_surfaces=(),
        ),
        "svc-idp": ServiceSpec(
            id="svc-idp",
            kind="idp",
            host="idp-1",
            ports=(389,),
            dependencies=(),
            telemetry_surfaces=(),
        ),
    }
    backend._service_zone_by_id = {"svc-web": "dmz", "svc-idp": "management"}
    backend._green_runner_by_zone = {
        "dmz": "sandbox-green-sales-01",
        "management": "sandbox-green-it-admin-01",
    }

    web_origin = Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-idp", "origin": "svc-web"},
    )
    idp_origin = Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={"target": "svc-idp", "origin": "svc-idp"},
    )

    assert backend._runner_for(web_origin) == "sandbox-green-sales-01"
    assert backend._runner_for(idp_origin) == "sandbox-green-it-admin-01"


def test_service_host_uses_release_namespace_when_bound() -> None:
    backend = PodActionBackend()
    backend._release = SimpleNamespace(release_name="or-demo")
    backend._service_zone_by_id = {"svc-web": "dmz", "svc-idp": "management"}

    assert backend._service_host("svc-web") == "svc-web.or-demo-dmz.svc.cluster.local"
    assert (
        backend._service_host("svc-idp")
        == "svc-idp.or-demo-management.svc.cluster.local"
    )
    assert backend._service_host("svc-unknown") == "svc-unknown"


def test_api_command_uses_explicit_http_port_for_non_web_service_paths() -> None:
    backend = PodActionBackend()
    backend._release = SimpleNamespace(release_name="or-demo")
    backend._service_by_id = {
        "svc-idp": ServiceSpec(
            id="svc-idp",
            kind="idp",
            host="idp-1",
            ports=(389, 8080),
            dependencies=(),
            telemetry_surfaces=(),
        )
    }
    backend._service_zone_by_id = {"svc-idp": "management"}

    command = backend._api_command(
        Action(
            actor_id="red",
            role="red",
            kind="api",
            payload={
                "target": "svc-idp",
                "port": 8080,
                "path": "/idp_admin_cred.txt",
            },
        )
    )

    assert (
        "http://svc-idp.or-demo-management.svc.cluster.local:8080/idp_admin_cred.txt"
        in command
    )
    assert "curl --max-time 5 -fsSL" in command


def test_api_command_preserves_http_method_headers_and_body() -> None:
    backend = PodActionBackend()
    backend._release = SimpleNamespace(release_name="or-demo")
    backend._service_by_id = {
        "svc-web": ServiceSpec(
            id="svc-web",
            kind="web_app",
            host="web-1",
            ports=(80,),
            dependencies=(),
            telemetry_surfaces=(),
        )
    }
    backend._service_zone_by_id = {"svc-web": "dmz"}

    command = backend._api_command(
        Action(
            actor_id="red",
            role="red",
            kind="api",
            payload={
                "target": "svc-web",
                "path": "/search.php",
                "method": "POST",
                "headers": {"Accept": "application/json"},
                "user_agent": "Mozilla/5.0",
                "body": "q=test",
            },
        )
    )

    assert "curl" in command
    assert " -X POST" in command
    assert "Accept: application/json" in command
    assert "User-Agent: Mozilla/5.0" in command
    assert "--data-raw" in command
    assert "http://svc-web.or-demo-dmz.svc.cluster.local:80/search.php" in command


def test_capture_integrity_hashes_or_marks_missing_live_paths() -> None:
    class FakePods:
        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            if service == "svc-web" and "index.html" in cmd:
                return ExecResult(stdout="present\tabc123\n", stderr="", exit_code=0)
            if service == "svc-web" and "broken.bin" in cmd:
                return ExecResult(
                    stdout="error\tno-sha256-tool\n", stderr="", exit_code=1
                )
            return ExecResult(stdout="missing\t\n", stderr="", exit_code=0)

    backend = PodActionBackend()
    backend._release = SimpleNamespace(pods=FakePods())

    samples = backend.capture_integrity(
        {
            "svc-web": (
                "/var/www/html/index.html",
                "/var/www/html/missing.php",
                "/usr/sbin/broken.bin",
            )
        }
    )

    assert samples == (
        IntegritySample(
            service_id="svc-web",
            path="/var/www/html/index.html",
            exists=True,
            digest="abc123",
        ),
        IntegritySample(
            service_id="svc-web",
            path="/var/www/html/missing.php",
            exists=False,
            digest="",
        ),
        IntegritySample(
            service_id="svc-web",
            path="/usr/sbin/broken.bin",
            probe_ok=False,
            exists=False,
            digest="",
        ),
    )


def test_http_fetch_command_uses_portable_fallback_chain() -> None:
    command = _http_fetch_command("http://svc-web:80/search.php?q=x", max_bytes=256)

    assert "curl --max-time 5 -fsSL" in command
    assert "wget -T 5 -qO-" in command
    assert "busybox wget -T 5 -qO-" in command
    assert "urlopen(sys.argv[1], timeout=5)" in command
    assert "stream_context_create" in command
    assert "timeout" in command
    assert "head -c 256" in command


def test_live_execution_blocks_red_target_local_shell_without_target_foothold() -> None:
    class FakePods:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            self.calls.append((service, cmd))
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service in {"svc-web", "svc-idp"}

    pods = FakePods()
    backend = PodActionBackend()
    backend._release = SimpleNamespace(pods=pods)
    backend._snapshot = SimpleNamespace(world=SimpleNamespace(weaknesses=()))
    backend._service_by_id = {
        "svc-web": ServiceSpec(
            id="svc-web",
            kind="web_app",
            host="web-1",
            ports=(80,),
            dependencies=(),
            telemetry_surfaces=(),
        ),
        "svc-idp": ServiceSpec(
            id="svc-idp",
            kind="idp",
            host="idp-1",
            ports=(389,),
            dependencies=(),
            telemetry_surfaces=(),
        ),
    }

    result = backend.execute(
        Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={
                "target": "svc-idp",
                "origin": "svc-web",
                "service_command": "cat /var/lib/openrange/secrets/idp_admin_cred.txt",
            },
        )
    )

    assert result.ok is False
    assert "requires a foothold on the target service" in result.stderr
    assert result.runner_service == "svc-web"
    assert result.target_service == "svc-idp"
    assert pods.calls == []


def test_live_execution_allows_red_target_local_shell_from_same_service_foothold() -> (
    None
):
    class FakePods:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        async def exec(
            self, service: str, cmd: str, timeout: float = 30.0
        ) -> ExecResult:
            del timeout
            self.calls.append((service, cmd))
            return ExecResult(stdout=f"{service}:{cmd}", stderr="", exit_code=0)

        async def is_healthy(self, service: str) -> bool:
            return service == "svc-web"

    pods = FakePods()
    backend = PodActionBackend()
    backend._release = SimpleNamespace(pods=pods)
    backend._snapshot = SimpleNamespace(world=SimpleNamespace(weaknesses=()))
    backend._service_by_id = {
        "svc-web": ServiceSpec(
            id="svc-web",
            kind="web_app",
            host="web-1",
            ports=(80,),
            dependencies=(),
            telemetry_surfaces=(),
        )
    }

    result = backend.execute(
        Action(
            actor_id="red",
            role="red",
            kind="shell",
            payload={
                "target": "svc-web",
                "origin": "svc-web",
                "service_command": "cat /var/www/html/index.php",
            },
        )
    )

    assert result.ok is True
    assert result.stdout == "svc-web:cat /var/www/html/index.php"
    assert pods.calls == [
        ("svc-web", "test ! -f /tmp/openrange-contained"),
        ("svc-web", "test ! -f /tmp/openrange-patched"),
        ("svc-web", "cat /var/www/html/index.php"),
    ]
