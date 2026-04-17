"""Live objective probing helpers."""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping

from open_range.objectives.common import (
    db_query_command,
    event_linked_predicates,
    event_target,
    event_type,
)
from open_range.objectives.effects import (
    effect_marker_path,
    effect_marker_service,
    effect_marker_token,
)
from open_range.objectives.models import ObjectiveGraderSpec
from open_range.support.async_utils import run_async


def evaluate_objective_grader_live(
    predicate: str,
    grader: ObjectiveGraderSpec,
    *,
    snapshot: object,
    pods: object,
    events: Iterable[object],
    service_health: Mapping[str, float],
    outputs: Iterable[str],
) -> bool:
    linked_events = [
        event for event in events if predicate in event_linked_predicates(event)
    ]
    combined_output = "\n".join(output for output in outputs if output)
    if grader.grader_kind == "event_present":
        matched = any(
            event_type(event) == grader.event_type
            and (not grader.target_id or event_target(event) == grader.target_id)
            for event in linked_events
        )
        if not matched:
            return False
        if grader.objective_tag in {"unauthorized_admin_login", "privilege_escalation"}:
            if _requires_effect_probe(snapshot, grader):
                return _probe_live_objective_effect(snapshot, pods, grader)
            if _matches_effect_output(grader, combined_output):
                return True
            return _probe_live_objective_effect(snapshot, pods, grader)
        return True
    if grader.grader_kind == "service_health":
        health = service_health.get(grader.service_id or grader.target_id, 1.0)
        return health < 0.9 or any(
            event_type(event) == "ServiceDegraded" for event in linked_events
        )
    if not getattr(pods, "exec", None):
        return False
    if grader.grader_kind == "file_exists":
        command = f"test -f {shlex.quote(grader.path)}"
        if grader.expected_ref:
            command += (
                f" && grep -q {shlex.quote(grader.expected_ref)} "
                f"{shlex.quote(grader.path)}"
            )
        result = run_async(pods.exec(grader.service_id, command, timeout=10.0))
        return result.ok and (
            grader.expected_ref in combined_output or bool(linked_events)
        )
    if grader.grader_kind == "db_row_read":
        query = db_query_command(
            snapshot,
            "SELECT contents FROM assets "
            f"WHERE asset_id = '{grader.target_id}' "
            "LIMIT 1;",
        )
        result = run_async(
            pods.exec(grader.service_id or "svc-db", query, timeout=10.0)
        )
        return (
            result.ok
            and bool(result.stdout.strip())
            and (
                grader.target_id in result.stdout
                or grader.expected_ref in result.stdout
            )
        )
    if grader.grader_kind == "db_row_write":
        query = db_query_command(
            snapshot,
            "SELECT COUNT(*) FROM assets "
            f"WHERE asset_id = '{grader.target_id}' "
            "LIMIT 1;",
        )
        result = run_async(
            pods.exec(grader.service_id or "svc-db", query, timeout=10.0)
        )
        return result.ok and result.stdout.strip() not in {"", "0"}
    if grader.grader_kind == "outbound_request":
        if not linked_events:
            return False
        if _requires_effect_probe(snapshot, grader):
            return _probe_live_objective_effect(snapshot, pods, grader)
        if _matches_effect_output(grader, combined_output):
            return True
        return _probe_live_objective_effect(snapshot, pods, grader)
    return False


def _probe_live_objective_effect(
    snapshot: object, pods: object, grader: ObjectiveGraderSpec
) -> bool:
    effect_paths = _effect_marker_specs(snapshot, grader)
    if effect_paths and _probe_effect_paths(pods, effect_paths):
        return True
    for weakness in _relevant_weaknesses(snapshot, grader):
        for service, command in _live_effect_probe_commands(weakness, grader):
            result = run_async(pods.exec(service, command, timeout=10.0))
            if result.ok:
                return True
    realizations = _relevant_realizations(snapshot, grader)
    return _probe_realizations(
        pods,
        realizations,
        expected_ref=grader.expected_ref,
        require_nonempty=True,
    )


def _requires_effect_probe(snapshot: object, grader: ObjectiveGraderSpec) -> bool:
    if grader.objective_tag not in {
        "unauthorized_admin_login",
        "privilege_escalation",
        "outbound_service",
    }:
        return False
    if _relevant_weaknesses(snapshot, grader):
        return True
    return bool(_relevant_realizations(snapshot, grader))


def _effect_marker_specs(
    snapshot: object, grader: ObjectiveGraderSpec
) -> tuple[tuple[str, str, str], ...]:
    matches: list[tuple[str, str, str]] = []
    for weakness in _relevant_weaknesses(snapshot, grader):
        service = effect_marker_service(weakness)
        path = effect_marker_path(weakness)
        token = effect_marker_token(weakness)
        if service and path:
            matches.append((service, path, token))
    return tuple(dict.fromkeys(matches))


def _relevant_weaknesses(
    snapshot: object, grader: ObjectiveGraderSpec
) -> tuple[object, ...]:
    world = getattr(snapshot, "world", None)
    weaknesses = getattr(world, "weaknesses", ()) if world is not None else ()
    matches: list[object] = []
    for weakness in weaknesses:
        objective_tags = tuple(getattr(weakness, "objective_tags", ()))
        if grader.objective_tag not in objective_tags:
            continue
        weakness_target = str(getattr(weakness, "target", ""))
        weakness_ref = str(getattr(weakness, "target_ref", ""))
        if grader.target_id and grader.target_id in {weakness_target, weakness_ref}:
            matches.append(weakness)
            continue
        if grader.service_id and grader.service_id == weakness_target:
            matches.append(weakness)
            continue
        if not grader.target_id and not grader.service_id:
            matches.append(weakness)
    return tuple(matches)


def _relevant_realizations(
    snapshot: object, grader: ObjectiveGraderSpec
) -> tuple[tuple[str, str], ...]:
    matches: list[tuple[str, str]] = []
    for weakness in _relevant_weaknesses(snapshot, grader):
        for realization in getattr(weakness, "realization", ()):
            service = str(getattr(realization, "service", ""))
            path = str(getattr(realization, "path", ""))
            if service and path:
                matches.append((service, path))
    return tuple(dict.fromkeys(matches))


def _live_effect_probe_commands(
    weakness: object,
    grader: ObjectiveGraderSpec,
) -> tuple[tuple[str, str], ...]:
    family = str(getattr(weakness, "family", ""))
    kind = str(getattr(weakness, "kind", ""))
    target = str(getattr(weakness, "target", ""))
    target_ref = str(getattr(weakness, "target_ref", ""))
    realizations = tuple(getattr(weakness, "realization", ()))
    commands: list[tuple[str, str]] = []

    if family == "config_identity":
        path = _first_realization_path(realizations, "config")
        if path:
            if kind == "weak_password":
                commands.append(
                    (
                        target,
                        _grep_all(
                            path,
                            '"min_password_length": 6',
                            '"password_reuse_allowed": true',
                        ),
                    )
                )
            elif kind == "default_credential":
                commands.append(
                    (
                        target,
                        _grep_all(
                            path,
                            '"default_username": "admin"',
                            '"default_password": "admin"',
                        ),
                    )
                )
            elif kind == "overbroad_service_account":
                commands.append(
                    (
                        target,
                        _grep_all(path, '"service_account_scope"', "svc-db", "svc-idp"),
                    )
                )
            elif kind == "admin_surface_exposed":
                commands.append(
                    (target, _grep_all(path, '"admin_surface_public": true'))
                )
            elif kind == "trust_edge_misconfig":
                commands.append(
                    (
                        target,
                        _grep_all(
                            path,
                            '"trust_scope": "corp-wide"',
                            '"peer_validation": false',
                        ),
                    )
                )

    if family == "workflow_abuse":
        workflow_path = _first_realization_path(realizations, "workflow")
        mailbox_path = _first_realization_path(realizations, "mailbox")
        if workflow_path:
            if kind == "helpdesk_reset_bypass":
                commands.append(
                    (
                        target,
                        _grep_all(
                            workflow_path,
                            '"identity_verification": "none"',
                            '"reset_without_ticket_owner": true',
                        ),
                    )
                )
            elif kind == "approval_chain_bypass":
                commands.append(
                    (
                        target,
                        _grep_all(workflow_path, '"secondary_approval_skipped": true'),
                    )
                )
            elif kind == "document_share_abuse":
                commands.append(
                    (
                        target,
                        _grep_all(workflow_path, '"share_visibility": "public_link"'),
                    )
                )
            elif kind == "phishing_credential_capture":
                commands.append(
                    (
                        target,
                        _grep_all(
                            workflow_path, '"credential_capture_landing": "/login"'
                        ),
                    )
                )
            elif kind == "internal_request_impersonation":
                commands.append(
                    (target, _grep_all(workflow_path, '"internal_alias_trust": true'))
                )
        if mailbox_path:
            commands.append(
                (
                    target,
                    _grep_any(mailbox_path, f"kind={kind}", "Subject:", target_ref),
                )
            )

    if family == "secret_exposure":
        for realization in realizations:
            service = str(getattr(realization, "service", "")) or target
            path = str(getattr(realization, "path", ""))
            kind_name = str(getattr(realization, "kind", ""))
            if not service or not path:
                continue
            if kind_name == "mailbox":
                commands.append(
                    (
                        service,
                        _grep_any(
                            path, "secret_material=", target_ref, grader.expected_ref
                        ),
                    )
                )
            elif kind == "backup_leak":
                commands.append(
                    (
                        service,
                        _grep_any(path, "INSERT INTO leaked_credentials", target_ref),
                    )
                )
            elif kind == "env_file_leak":
                commands.append(
                    (
                        service,
                        _grep_any(path, "OPENRANGE_APP_SECRET=", "OPENRANGE_WORLD_ID="),
                    )
                )
            elif kind == "hardcoded_app_secret":
                commands.append(
                    (
                        service,
                        _grep_any(
                            path, "OPENRANGE_APP_SECRET", "define('OPENRANGE_WORLD_ID'"
                        ),
                    )
                )
            else:
                commands.append((service, _nonempty_file(path)))

    if family == "code_web":
        code_paths = [
            str(getattr(realization, "path", ""))
            for realization in realizations
            if getattr(realization, "kind", "") == "code"
        ]
        seed_paths = [
            str(getattr(realization, "path", ""))
            for realization in realizations
            if getattr(realization, "kind", "") == "seed_data"
        ]
        if kind == "auth_bypass" and code_paths:
            commands.append(
                (target, _grep_all(code_paths[0], "impersonate", "$debug === '1'"))
            )
        elif kind == "command_injection" and code_paths:
            commands.append(
                (target, _grep_all(code_paths[0], "shell_exec", "printf 'scan=%s"))
            )
        elif kind == "ssrf" and code_paths:
            parts = [_grep_all(code_paths[0], "file_get_contents($url")]
            if seed_paths:
                commands.append(
                    (
                        effect_marker_service(weakness),
                        _grep_any(
                            seed_paths[0], effect_marker_token(weakness), weakness.id
                        ),
                    )
                )
            commands.append((target, " && ".join(parts)))

    return tuple(commands)


def _probe_realizations(
    pods: object,
    realizations: tuple[tuple[str, str], ...],
    *,
    expected_ref: str,
    require_nonempty: bool = False,
) -> bool:
    if not realizations:
        return False
    for service, path in realizations:
        command = f"test -f {shlex.quote(path)}"
        if expected_ref:
            command += f" && grep -q {shlex.quote(expected_ref)} {shlex.quote(path)}"
        elif require_nonempty:
            command += f" && test -s {shlex.quote(path)}"
        result = run_async(pods.exec(service, command, timeout=10.0))
        if result.ok:
            return True
    return False


def _probe_effect_paths(
    pods: object,
    effect_paths: tuple[tuple[str, str, str], ...],
) -> bool:
    for service, path, token in effect_paths:
        command = f"test -f {shlex.quote(path)}"
        if token:
            command += f" && grep -Fq {shlex.quote(token)} {shlex.quote(path)}"
        else:
            command += f" && test -s {shlex.quote(path)}"
        result = run_async(pods.exec(service, command, timeout=10.0))
        if result.ok:
            return True
    return False


def _first_realization_path(realizations: tuple[object, ...], kind: str) -> str:
    for realization in realizations:
        if str(getattr(realization, "kind", "")) != kind:
            continue
        path = str(getattr(realization, "path", ""))
        if path:
            return path
    return ""


def _grep_all(path: str, *needles: str) -> str:
    parts = [f"test -f {shlex.quote(path)}"]
    for needle in needles:
        if needle:
            parts.append(f"grep -Fq {shlex.quote(needle)} {shlex.quote(path)}")
    return " && ".join(parts)


def _grep_any(path: str, *needles: str) -> str:
    clauses = [
        f"grep -Fq {shlex.quote(needle)} {shlex.quote(path)}"
        for needle in needles
        if needle
    ]
    if not clauses:
        return _nonempty_file(path)
    return f"test -f {shlex.quote(path)} && (" + " || ".join(clauses) + ")"


def _nonempty_file(path: str) -> str:
    return f"test -f {shlex.quote(path)} && test -s {shlex.quote(path)}"


def _matches_effect_output(grader: ObjectiveGraderSpec, combined_output: str) -> bool:
    text = combined_output.lower()
    if not text.strip():
        return False
    return any(token in text for token in _effect_tokens(grader))


def _effect_tokens(grader: ObjectiveGraderSpec) -> tuple[str, ...]:
    tokens = {
        token.strip().lower()
        for token in (
            grader.expected_ref,
            grader.target_id,
            grader.service_id,
        )
        if token
    }
    if grader.objective_tag == "unauthorized_admin_login":
        tokens.update(
            {
                "admin",
                "admin_surface",
                "default_password",
                "identity_verification",
                "credential_capture",
                "impersonate",
                "openrange-foothold:",
            }
        )
    elif grader.objective_tag == "privilege_escalation":
        tokens.update(
            {
                "privilege",
                "service_account_scope",
                "trust_scope",
                "target_ref",
                "openrange-foothold:",
            }
        )
    elif grader.objective_tag == "outbound_service":
        tokens.update(
            {
                "openrange-effect:egress:",
                "openrange-egress",
                "fetch",
            }
        )
    return tuple(sorted(tokens))
