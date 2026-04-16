from __future__ import annotations

from open_range.runtime_events import (
    control_directive,
    control_directive_from_payload,
    finding_event_type,
    finding_event_type_from_payload,
)
from open_range.runtime_types import Action


def test_control_directive_helpers_keep_current_defaults() -> None:
    action = Action(
        actor_id="blue",
        role="blue",
        kind="control",
        payload={"target": "svc-web"},
    )

    assert control_directive(action, default="contain") == "contain"
    assert control_directive_from_payload({}, default="contain") == "contain"
    assert control_directive_from_payload({"action": "MiTiGaTe"}) == "mitigate"


def test_finding_event_type_helpers_prefer_explicit_event_type() -> None:
    action = Action(
        actor_id="blue",
        role="blue",
        kind="submit_finding",
        payload={"event": "InitialAccess", "event_type": "CredentialObtained"},
    )

    assert finding_event_type(action) == "CredentialObtained"
    assert (
        finding_event_type_from_payload(
            {"event": "InitialAccess", "event_type": "CredentialObtained"},
            default="InitialAccess",
        )
        == "CredentialObtained"
    )
    assert (
        finding_event_type_from_payload({}, default="InitialAccess") == "InitialAccess"
    )
