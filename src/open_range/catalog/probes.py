"""Catalog-backed defaults for admission probe planning."""

from __future__ import annotations

from collections.abc import Mapping

from open_range.catalog.contracts import (
    BlueReferencePlanSpec,
    ProbeTemplateSpec,
    ShortcutWebRouteProbeSpec,
)

DEFAULT_SHORTCUT_PROBE_TEMPLATES: tuple[ProbeTemplateSpec, ...] = (
    ProbeTemplateSpec(
        id="shortcut-direct-asset",
        kind="shortcut",
        description="direct external crown-jewel access",
    ),
    ProbeTemplateSpec(
        id="shortcut-admin",
        kind="shortcut",
        description="direct admin access",
    ),
    ProbeTemplateSpec(
        id="shortcut-cross-zone",
        kind="shortcut",
        description="unintended cross-zone reachability",
    ),
    ProbeTemplateSpec(
        id="shortcut-secret",
        kind="shortcut",
        description="leaked secrets",
    ),
    ProbeTemplateSpec(
        id="shortcut-unlogged",
        kind="shortcut",
        description="unlogged critical actions",
    ),
)

DEFAULT_DETERMINISM_PROBE_TEMPLATES: tuple[ProbeTemplateSpec, ...] = (
    ProbeTemplateSpec(
        id="determinism-red",
        kind="determinism",
        description="replay red reference",
    ),
)

SHORTCUT_WEB_ROUTE_PROBE_SPECS: tuple[ShortcutWebRouteProbeSpec, ...] = (
    ShortcutWebRouteProbeSpec(
        weakness_kind="sql_injection",
        path="/search.php",
        query=(("q", "' UNION SELECT 'shortcut' -- "), ("asset", "finance_docs")),
    ),
    ShortcutWebRouteProbeSpec(
        weakness_kind="broken_authorization",
        path="/records.php",
        query=(("record", "admin-console"), ("viewer", "sales-01")),
    ),
    ShortcutWebRouteProbeSpec(
        weakness_kind="auth_bypass",
        path="/admin.php",
        query=(("debug", "1"), ("as", "admin")),
    ),
)

_BLUE_NON_DETECTABLE_ACTIONS = frozenset(("deliver_phish", "deliver_lure"))
_BLUE_INITIAL_ACCESS_ACTIONS = frozenset(("initial_access", "click_lure"))
_BLUE_CREDENTIAL_OR_SECRET_ACTIONS = frozenset(
    ("collect_secret", "abuse_identity", "abuse_workflow")
)
_EMAIL_DELIVERY_WORKFLOW_KINDS = frozenset(
    ("phishing_credential_capture", "internal_request_impersonation")
)
_REFERENCE_ACTION_BY_WEAKNESS_FAMILY = {
    "secret_exposure": "collect_secret",
    "config_identity": "abuse_identity",
    "workflow_abuse": "abuse_workflow",
}
_RED_REFERENCE_FAMILY_PRIORITY = {
    "code_web": 0,
    "workflow_abuse": 1,
    "secret_exposure": 1,
    "config_identity": 1,
    "telemetry_blindspot": 2,
}
_PRIMARY_RED_REFERENCE_FAMILY_ALLOWLIST = frozenset(
    family
    for family in _RED_REFERENCE_FAMILY_PRIORITY
    if family != "telemetry_blindspot"
)
_BLUE_REFERENCE_EXPECTED_EVENTS = ("DetectionAlertRaised", "ContainmentApplied")
_IDENTITY_EFFECT_MARKERS_BY_KIND = {
    "weak_password": ('"min_password_length": 6', '"password_reuse_allowed": true'),
    "default_credential": (
        '"default_username": "admin"',
        '"default_password": "admin"',
    ),
    "overbroad_service_account": ('"service_account_scope"', "svc-db", "svc-idp"),
    "admin_surface_exposed": ('"admin_surface_public": true',),
    "trust_edge_misconfig": (
        '"trust_scope": "corp-wide"',
        '"peer_validation": false',
    ),
}
_WORKFLOW_EFFECT_MARKERS_BY_KIND = {
    "helpdesk_reset_bypass": (
        '"identity_verification": "none"',
        '"reset_without_ticket_owner": true',
    ),
    "approval_chain_bypass": ('"secondary_approval_skipped": true',),
    "document_share_abuse": ('"share_visibility": "public_link"',),
    "phishing_credential_capture": ('"credential_capture_landing": "/login"',),
    "internal_request_impersonation": ('"internal_alias_trust": true',),
}


def smoke_probe_template(service_id: str) -> ProbeTemplateSpec:
    return ProbeTemplateSpec(
        id=f"smoke-{service_id}",
        kind="smoke",
        description=f"boot and basic health for {service_id}",
        command=f"check {service_id}",
    )


def necessity_probe_template(weakness_id: str) -> ProbeTemplateSpec:
    return ProbeTemplateSpec(
        id=f"necessity-{weakness_id}",
        kind="necessity",
        description=f"remove or remediate {weakness_id} and require reference degradation",
    )


def detection_for_reference_step_action(
    action: str,
    *,
    target: str = "",
    asset: str = "",
    objective: str = "",
) -> tuple[str, str]:
    if action in _BLUE_INITIAL_ACCESS_ACTIONS:
        return ("InitialAccess", target)
    if action == "traverse":
        return ("CrossZoneTraversal", target)
    if action in _BLUE_CREDENTIAL_OR_SECRET_ACTIONS:
        resolved_target = asset or target
        if asset and ("cred" in asset or "token" in asset):
            return ("CredentialObtained", resolved_target)
        return ("SensitiveAssetRead", resolved_target)
    if action == "satisfy_objective" and objective.startswith("credential_obtained("):
        return ("CredentialObtained", asset or target)
    if action == "satisfy_objective":
        return ("SensitiveAssetRead", asset or target)
    return ("InitialAccess", target or "svc-web")


def is_blue_detectable_action(
    action: str,
    *,
    target: str = "",
    source_target: str = "",
    blindspot_targets: frozenset[str] | set[str],
) -> bool:
    if action in _BLUE_NON_DETECTABLE_ACTIONS:
        return False
    if action in _BLUE_INITIAL_ACCESS_ACTIONS:
        return target not in blindspot_targets
    if action == "traverse":
        return (
            target not in blindspot_targets and source_target not in blindspot_targets
        )
    return target not in blindspot_targets


def telemetry_blindspot_targets(world) -> frozenset[str]:
    return frozenset(
        weak.target for weak in world.weaknesses if weak.family == "telemetry_blindspot"
    )


def blue_reference_plan_for_trace(
    red_trace,
    *,
    blindspot_targets: frozenset[str] | set[str],
) -> BlueReferencePlanSpec:
    detect_index = next(
        (
            index
            for index, step in enumerate(red_trace.steps)
            if is_blue_detectable_action(
                str(step.payload.get("action", "")),
                target=step.target,
                source_target=(red_trace.steps[index - 1].target if index > 0 else ""),
                blindspot_targets=blindspot_targets,
            )
        ),
        0,
    )
    detect_step = red_trace.steps[detect_index] if red_trace.steps else None
    detect_event, detect_target = detection_for_reference_step_action(
        str(detect_step.payload.get("action", "")) if detect_step else "",
        target=detect_step.target if detect_step else "",
        asset=str(detect_step.payload.get("asset", "")) if detect_step else "",
        objective=(
            str(detect_step.payload.get("objective", "")) if detect_step else ""
        ),
    )
    return BlueReferencePlanSpec(
        detect_index=detect_index,
        detect_event=detect_event,
        detect_target=detect_target,
        contain_target=red_trace.steps[-1].target if red_trace.steps else "svc-siem",
        observe_step_count=max(1, detect_index + 1),
    )


def blue_reference_expected_events() -> tuple[str, str]:
    return _BLUE_REFERENCE_EXPECTED_EVENTS


def blue_observe_reference_payload() -> dict[str, str]:
    return {"action": "observe_events"}


def blue_submit_finding_payload(*, detect_event: str) -> dict[str, str]:
    return {"event": detect_event}


def blue_containment_payload() -> dict[str, str]:
    return {"action": "contain"}


def runtime_payload_for_reference_action(
    actor: str,
    kind: str,
    *,
    target: str = "",
    payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    next_payload: dict[str, object] = dict(payload or {})
    if target:
        next_payload.setdefault("target", target)
    if actor == "blue" and kind == "submit_finding":
        next_payload["event_type"] = str(
            next_payload.get(
                "event",
                next_payload.get("event_type", "InitialAccess"),
            )
        )
    return next_payload


def workflow_kind_uses_email_delivery(kind: str) -> bool:
    return kind in _EMAIL_DELIVERY_WORKFLOW_KINDS


def reference_action_for_weakness_family(family: str) -> str:
    return _REFERENCE_ACTION_BY_WEAKNESS_FAMILY.get(family, "")


def red_reference_family_priority(family: str) -> int:
    return _RED_REFERENCE_FAMILY_PRIORITY.get(family, 1)


def family_supports_primary_red_reference(family: str) -> bool:
    return family in _PRIMARY_RED_REFERENCE_FAMILY_ALLOWLIST


def identity_effect_markers_for_kind(kind: str) -> tuple[str, ...]:
    return _IDENTITY_EFFECT_MARKERS_BY_KIND.get(kind, ())


def workflow_effect_markers_for_kind(kind: str) -> tuple[str, ...]:
    return _WORKFLOW_EFFECT_MARKERS_BY_KIND.get(kind, ())
