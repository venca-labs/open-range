"""Concrete live-effect marker helpers for grounded objective validation."""

from __future__ import annotations

import shlex


def effect_scope(weakness: object) -> str:
    objective_tags = tuple(getattr(weakness, "objective_tags", ()))
    if "unauthorized_admin_login" in objective_tags:
        return "admin"
    if "privilege_escalation" in objective_tags:
        return "privilege"
    if "outbound_service" in objective_tags:
        return "egress"
    return ""


def effect_marker_path(weakness: object) -> str:
    scope = effect_scope(weakness)
    if not scope:
        return ""
    weak_id = getattr(weakness, "id", "unknown")
    if scope == "egress":
        return f"/srv/http/siem/egress-canary-{weak_id}.log"
    return f"/var/lib/openrange/effects/{scope}-{weak_id}.txt"


def effect_marker_service(weakness: object) -> str:
    scope = effect_scope(weakness)
    if scope == "egress":
        return "svc-siem"
    return getattr(weakness, "target", "")


def effect_marker_token(weakness: object) -> str:
    scope = effect_scope(weakness)
    if not scope:
        return ""
    weak_id = getattr(weakness, "id", "unknown")
    if scope == "egress":
        return f"OPENRANGE-EFFECT:egress:{weak_id}"
    target_ref = getattr(weakness, "target_ref", "") or getattr(weakness, "target", "")
    return f"OPENRANGE-EFFECT:{scope}:{weak_id}:{target_ref}"


def effect_marker_content(weakness: object) -> str:
    token = effect_marker_token(weakness)
    if not token:
        return ""
    return (
        f"{token}\n"
        f"weakness_id={getattr(weakness, 'id', 'unknown')}\n"
        f"target={getattr(weakness, 'target', '')}\n"
        f"target_ref={getattr(weakness, 'target_ref', '') or getattr(weakness, 'target', '')}\n"
    )


def effect_marker_cleanup_command(weakness: object) -> str:
    path = effect_marker_path(weakness)
    if not path:
        return ""
    return f"rm -f {shlex.quote(path)}"
