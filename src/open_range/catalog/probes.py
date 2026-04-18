"""Catalog-backed defaults for admission probe planning."""

from __future__ import annotations

from collections.abc import Mapping

from open_range.catalog.contracts import (
    ProbeTemplateSpec,
    ShortcutWebRouteProbeSpec,
)
from open_range.contracts.runtime import finding_event_type_from_payload

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
        next_payload["event_type"] = finding_event_type_from_payload(
            next_payload,
            default="InitialAccess",
        )
    return next_payload


def red_reference_starts(
    service_ids: tuple[str, ...],
    *,
    public_service_ids: tuple[str, ...],
) -> tuple[str, ...]:
    if public_service_ids:
        return public_service_ids
    return service_ids[:1]


def ordered_red_reference_candidates(
    starts: tuple[str, ...],
    weaknesses,
) -> tuple[tuple[str, object | None], ...]:
    ranked = sorted(
        weaknesses,
        key=lambda weakness: _red_reference_sort_key(
            weakness,
            preferred_targets=frozenset(starts),
        ),
    )
    candidates = tuple(
        (start, weakness)
        for weakness in ranked
        for start in _ordered_starts_for_target(starts, _weakness_target(weakness))
    )
    if candidates:
        return candidates
    if not starts:
        return ()
    return ((starts[0], None),)


def select_primary_red_reference_weakness(start: str, weaknesses):
    ranked = [
        weakness
        for weakness in weaknesses
        if family_supports_primary_red_reference(_weakness_family(weakness))
    ]
    if not ranked:
        return next(iter(weaknesses), None)
    ranked.sort(
        key=lambda weakness: _red_reference_sort_key(
            weakness,
            preferred_targets=frozenset((start,)),
        )
    )
    return ranked[0]


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


def _red_reference_sort_key(
    weakness,
    *,
    preferred_targets: frozenset[str],
) -> tuple[int, int, str]:
    return (
        0 if _weakness_target(weakness) in preferred_targets else 1,
        red_reference_family_priority(_weakness_family(weakness)),
        _weakness_id(weakness),
    )


def _ordered_starts_for_target(
    starts: tuple[str, ...],
    target: str,
) -> tuple[str, ...]:
    if target in starts:
        return (target,) + tuple(start for start in starts if start != target)
    return starts


def _weakness_family(weakness) -> str:
    return str(getattr(weakness, "family", ""))


def _weakness_id(weakness) -> str:
    return str(getattr(weakness, "id", ""))


def _weakness_target(weakness) -> str:
    return str(getattr(weakness, "target", ""))
