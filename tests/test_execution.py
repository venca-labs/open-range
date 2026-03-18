from __future__ import annotations

import shlex

import pytest

from open_range.execution import PodActionBackend
from open_range.runtime_types import Action
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
