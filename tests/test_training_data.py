from __future__ import annotations

from open_range.contracts.runtime import Action, RuntimeEvent
from open_range.training.trace_exports import (
    grounded_effects_for_result,
    mitigation_effects_for_result,
    public_trace_action,
    render_action_text,
)


def test_public_trace_action_strips_internal_execution_payload() -> None:
    action = Action(
        actor_id="red",
        role="red",
        kind="shell",
        payload={
            "target": "svc-idp",
            "command": "cat /etc/openrange/admin-surface.json",
            "service_command": "grep -Fq admin /etc/openrange/admin-surface.json",
        },
    )

    public = public_trace_action(action)

    assert "service_command" not in public.payload
    assert public.payload["command"] == "cat /etc/openrange/admin-surface.json"


def test_grounded_and_mitigation_effect_helpers_extract_runtime_signals() -> None:
    events = (
        RuntimeEvent(
            id="evt-1",
            event_type="PrivilegeEscalation",
            actor="red",
            time=1.0,
            source_entity="svc-idp",
            target_entity="idp_admin_cred",
            malicious=True,
        ),
        RuntimeEvent(
            id="evt-2",
            event_type="PatchApplied",
            actor="blue",
            time=2.0,
            source_entity="blue",
            target_entity="svc-idp",
            malicious=False,
        ),
    )

    grounded = grounded_effects_for_result(
        stdout="OPENRANGE-EFFECT:privilege:wk-1:svc-idp", emitted_events=events
    )
    mitigations = mitigation_effects_for_result(
        action=Action(
            actor_id="blue",
            role="blue",
            kind="control",
            payload={"target": "svc-idp", "action": "mitigate"},
        ),
        stdout="mitigation applied to svc-idp",
        emitted_events=events,
    )

    assert "PrivilegeEscalation" in grounded
    assert any(item.startswith("OPENRANGE-EFFECT:privilege:") for item in grounded)
    assert "PatchApplied" in mitigations
    assert "mitigate:svc-idp" in mitigations


def test_render_action_text_keeps_http_semantics() -> None:
    action = Action(
        actor_id="red",
        role="red",
        kind="api",
        payload={
            "target": "svc-web",
            "path": "/search.php",
            "query": {"q": "test"},
            "method": "POST",
            "headers": {"Accept": "application/json"},
            "user_agent": "Mozilla/5.0",
            "body": "q=test",
        },
    )

    rendered = render_action_text(action)

    assert rendered.startswith("curl -s -X POST")
    assert '-A "Mozilla/5.0"' in rendered
    assert '-H "Accept: application/json"' in rendered
    assert '--data-raw "q=test"' in rendered
    assert rendered.endswith("http://svc-web/search.php?q=test")
