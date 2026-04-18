from __future__ import annotations

from open_range.contracts.runtime import Action
from open_range.training.trace_exports import (
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
