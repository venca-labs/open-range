from __future__ import annotations

import shlex
from types import SimpleNamespace

import pytest

from open_range.cluster import ExecResult
from open_range.execution import PodActionBackend
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
