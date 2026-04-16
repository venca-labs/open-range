"""Catalog-backed defaults for admission probe planning."""

from __future__ import annotations

from open_range.catalog.contracts import ProbeTemplateSpec, ShortcutWebRouteProbeSpec

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
