"""Lightweight action auditing and integrity checks for runtime episodes."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from open_range.config import AuditConfig
from open_range.contracts.runtime import (
    Action,
    ActionDiversitySummary,
    AuditActionRecord,
    BinaryIntegritySummary,
    EpisodeAudit,
    ExternalRole,
    IntegrityDelta,
    IntegritySample,
    IntegrityServiceSummary,
    action_target,
    control_directive,
    finding_event_type,
)
from open_range.contracts.snapshot import RuntimeSnapshot

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_VOLATILE_INTEGRITY_SUFFIXES = (".log",)
_SHELL_WRAPPER_NAMES = {"ash", "bash", "dash", "ksh", "sh", "zsh"}
_DEFAULT_BINARY_PATHS_BY_KIND = {
    "web_app": ("/usr/local/bin/apache2-foreground", "/usr/sbin/apache2"),
    "email": ("/usr/sbin/sendmail", "/usr/sbin/exim4", "/usr/sbin/postfix"),
    "idp": ("/container/tool/run", "/usr/sbin/slapd"),
    "fileshare": ("/usr/bin/samba.sh", "/usr/sbin/smbd"),
    "db": ("/usr/local/bin/docker-entrypoint.sh", "/usr/sbin/mysqld"),
    "siem": ("/bin/busybox",),
}


@dataclass(frozen=True, slots=True)
class ActionAuditObservation:
    actor: ExternalRole
    sim_time: float
    action_kind: str
    target: str
    command: str
    fingerprint: str
    fingerprint_prefix: str
    matched_patterns: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return bool(self.matched_patterns)


class ActionAuditor:
    """Classify controlled actions without changing runtime behavior."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self._compiled_patterns = _compile_patterns(config.suspicious_patterns)
        self._records: list[AuditActionRecord] = []
        self._integrity_targets: dict[str, tuple[str, ...]] = {}
        self._integrity_expected_keys: set[tuple[str, str]] = set()
        self._integrity_expected_keys_by_service: dict[str, set[tuple[str, str]]] = {}
        self._integrity_baseline: dict[tuple[str, str], IntegritySample] = {}
        self._integrity_baseline_available_by_service: dict[str, bool] = {}
        self._integrity_available = False

    def bind_snapshot(self, snapshot: RuntimeSnapshot) -> None:
        self._integrity_targets = integrity_targets_for_snapshot(snapshot, self.config)
        self._integrity_expected_keys_by_service = {
            service_id: {(service_id, path) for path in paths}
            for service_id, paths in self._integrity_targets.items()
        }
        self._integrity_expected_keys = {
            (service_id, path)
            for service_id, paths in self._integrity_targets.items()
            for path in paths
        }
        self._integrity_baseline = {}
        self._integrity_baseline_available_by_service = {}
        self._integrity_available = False

    def capture_baseline(
        self,
        capture_integrity: Callable[
            [dict[str, tuple[str, ...]]], tuple[IntegritySample, ...]
        ]
        | None,
    ) -> None:
        if not self.config.enabled or not self.config.binary_integrity_enabled:
            return
        if not callable(capture_integrity) or not self._integrity_targets:
            return
        samples = capture_integrity(self._integrity_targets)
        self._integrity_baseline = self._integrity_sample_map(samples)
        self._integrity_baseline_available_by_service = (
            self._integrity_service_availability(self._integrity_baseline)
        )
        self._integrity_available = any(
            self._integrity_baseline_available_by_service.values()
        )

    def observe(
        self,
        *,
        action: Action,
        executed_command: str,
        audit_command: str = "",
        sim_time: float,
        controlled: bool,
    ) -> ActionAuditObservation | None:
        if (
            not self.config.enabled
            or not controlled
            or action.role not in {"red", "blue"}
        ):
            return None
        target = action_target(action)
        command = audit_command_for_action(
            action,
            audit_command=audit_command or command_text_for_action(action),
            executed_command=executed_command,
        )
        fingerprint_prefix = fingerprint_prefix_for_command(
            command or fallback_fingerprint_source(action),
            token_limit=self.config.fingerprint_token_limit,
        )
        matched_patterns = match_suspicious_patterns(command, self._compiled_patterns)
        return ActionAuditObservation(
            actor=action.role,
            sim_time=round(sim_time, 4),
            action_kind=action.kind,
            target=target,
            command=command,
            fingerprint=hashlib.sha256(fingerprint_prefix.encode("utf-8")).hexdigest()[
                :8
            ],
            fingerprint_prefix=fingerprint_prefix,
            matched_patterns=matched_patterns,
        )

    def record(
        self,
        observation: ActionAuditObservation | None,
        *,
        emitted_event_ids: tuple[str, ...],
    ) -> None:
        if observation is None:
            return
        self._records.append(
            AuditActionRecord(
                actor=observation.actor,
                sim_time=observation.sim_time,
                action_kind=observation.action_kind,
                target=observation.target,
                command=_truncate(observation.command),
                fingerprint=observation.fingerprint,
                fingerprint_prefix=observation.fingerprint_prefix,
                matched_patterns=observation.matched_patterns,
                emitted_event_ids=emitted_event_ids,
            )
        )

    def build_summary(
        self,
        capture_integrity: Callable[
            [dict[str, tuple[str, ...]]], tuple[IntegritySample, ...]
        ]
        | None = None,
    ) -> EpisodeAudit:
        if not self.config.enabled:
            return EpisodeAudit(binary_integrity=BinaryIntegritySummary(enabled=False))

        total_actions = len(self._records)
        fingerprints = {record.fingerprint for record in self._records}
        overall_diversity = (
            round(len(fingerprints) / total_actions, 4) if total_actions else 1.0
        )
        suspicious_actions = tuple(
            record for record in self._records if record.matched_patterns
        )
        suspicious_event_ids = tuple(
            sorted(
                {
                    event_id
                    for record in suspicious_actions
                    for event_id in record.emitted_event_ids
                }
            )
        )
        role_diversity = tuple(
            self._role_diversity_summary(actor)
            for actor in ("red", "blue")
            if any(record.actor == actor for record in self._records)
        )
        collapse_warning = any(entry.collapse_warning for entry in role_diversity)
        return EpisodeAudit(
            action_count=total_actions,
            unique_fingerprints=len(fingerprints),
            action_diversity_score=overall_diversity,
            collapse_warning=collapse_warning,
            suspicious_actions=suspicious_actions,
            suspicious_event_ids=suspicious_event_ids,
            role_diversity=role_diversity,
            binary_integrity=self._binary_integrity_summary(capture_integrity),
        )

    def _role_diversity_summary(self, actor: ExternalRole) -> ActionDiversitySummary:
        records = [record for record in self._records if record.actor == actor]
        total_actions = len(records)
        counts = Counter(record.fingerprint for record in records)
        unique_fingerprints = len(counts)
        diversity_score = (
            round(unique_fingerprints / total_actions, 4) if total_actions else 1.0
        )
        dominant_fingerprint = ""
        dominant_prefix = ""
        dominant_share = 0.0
        if counts:
            dominant_fingerprint, dominant_count = max(
                counts.items(), key=lambda item: (item[1], item[0])
            )
            dominant_prefix = next(
                record.fingerprint_prefix
                for record in records
                if record.fingerprint == dominant_fingerprint
            )
            dominant_share = round(dominant_count / total_actions, 4)
        collapse_warning = (
            total_actions >= self.config.minimum_actions_for_collapse
            and diversity_score < self.config.diversity_warning_threshold
        )
        return ActionDiversitySummary(
            actor=actor,
            total_actions=total_actions,
            unique_fingerprints=unique_fingerprints,
            diversity_score=diversity_score,
            dominant_fingerprint=dominant_fingerprint,
            dominant_fingerprint_prefix=dominant_prefix,
            dominant_share=dominant_share,
            collapse_warning=collapse_warning,
        )

    def _binary_integrity_summary(
        self,
        capture_integrity: Callable[
            [dict[str, tuple[str, ...]]], tuple[IntegritySample, ...]
        ]
        | None,
    ) -> BinaryIntegritySummary:
        if not self.config.binary_integrity_enabled:
            return BinaryIntegritySummary(enabled=False)
        checked_services = tuple(sorted(self._integrity_targets))
        checked_paths = sum(len(paths) for paths in self._integrity_targets.values())
        if not checked_services or not callable(capture_integrity):
            return BinaryIntegritySummary(
                enabled=True,
                available=False,
                checked_services=checked_services,
                unavailable_services=checked_services,
                checked_paths=checked_paths,
            )
        current_samples = capture_integrity(self._integrity_targets)
        current_map = self._integrity_sample_map(current_samples)
        current_available_by_service = self._integrity_service_availability(current_map)
        deltas: list[IntegrityDelta] = []
        changed_services: list[str] = []
        unchanged_services: list[str] = []
        available_services: list[str] = []
        unavailable_services: list[str] = []
        service_summaries: list[IntegrityServiceSummary] = []
        for service_id in checked_services:
            service_paths = self._integrity_targets.get(service_id, ())
            if not (
                self._integrity_baseline_available_by_service.get(service_id, False)
                and current_available_by_service.get(service_id, False)
            ):
                unavailable_services.append(service_id)
                service_summaries.append(
                    IntegrityServiceSummary(
                        service_id=service_id,
                        available=False,
                        checked_paths=len(service_paths),
                    )
                )
                continue
            available_services.append(service_id)
            service_deltas: list[IntegrityDelta] = []
            for key in sorted(
                self._integrity_expected_keys_by_service.get(service_id, ())
            ):
                baseline = self._integrity_baseline.get(key)
                current = current_map.get(key)
                if baseline is None or current is None:
                    continue
                if (
                    baseline.exists != current.exists
                    or baseline.digest != current.digest
                ):
                    service_deltas.append(
                        IntegrityDelta(
                            service_id=service_id,
                            path=baseline.path,
                            before_exists=baseline.exists,
                            after_exists=current.exists,
                            before_digest=baseline.digest,
                            after_digest=current.digest,
                        )
                    )
            deltas.extend(service_deltas)
            if service_deltas:
                changed_services.append(service_id)
            else:
                unchanged_services.append(service_id)
            service_summaries.append(
                IntegrityServiceSummary(
                    service_id=service_id,
                    available=True,
                    checked_paths=len(service_paths),
                    changed_paths=tuple(service_deltas),
                    unchanged_paths=len(service_paths) - len(service_deltas),
                )
            )
        return BinaryIntegritySummary(
            enabled=True,
            available=bool(available_services),
            checked_services=checked_services,
            available_services=tuple(available_services),
            unavailable_services=tuple(unavailable_services),
            checked_paths=checked_paths,
            changed_services=tuple(changed_services),
            unchanged_services=tuple(unchanged_services),
            changed_paths=tuple(deltas),
            service_summaries=tuple(service_summaries),
        )

    @staticmethod
    def _integrity_sample_map(
        samples: tuple[IntegritySample, ...],
    ) -> dict[tuple[str, str], IntegritySample]:
        return {(sample.service_id, sample.path): sample for sample in samples}

    def _integrity_service_availability(
        self, sample_map: dict[tuple[str, str], IntegritySample]
    ) -> dict[str, bool]:
        return {
            service_id: bool(expected_keys)
            and expected_keys.issubset(sample_map)
            and all(sample_map[key].probe_ok for key in expected_keys)
            for service_id, expected_keys in self._integrity_expected_keys_by_service.items()
        }


def command_text_for_action(action: Action) -> str:
    """Return a stable textual action description for audit classification."""

    target = action_target(action)
    if action.kind == "shell":
        return str(
            action.payload.get("service_command", action.payload.get("command", ""))
        ).strip()
    if action.kind == "mail":
        sender = str(action.payload.get("from", action.actor_id))
        recipient = str(action.payload.get("to", "noreply@corp.local"))
        subject = str(action.payload.get("subject", "routine update"))
        return f"mail {target or 'svc-email'} {sender} {recipient} {subject}"
    if action.kind == "api":
        method = str(action.payload.get("method", "")).strip().upper()
        path = str(action.payload.get("path", "/") or "/")
        query = action.payload.get("query", {})
        query_text = ""
        if isinstance(query, dict) and query:
            query_text = " " + json.dumps(query, sort_keys=True, separators=(",", ":"))
        method_text = f"{method} " if method else ""
        return f"api {method_text}{target} {path}{query_text}".strip()
    if action.kind == "control":
        directive = control_directive(action, default="contain")
        return f"{directive} {target}".strip()
    if action.kind == "submit_finding":
        event_type = finding_event_type(action)
        return f"submit_finding {event_type} {target}".strip()
    if action.kind == "chat":
        sender = str(action.payload.get("from", action.actor_id))
        message = str(action.payload.get("message", ""))[:64]
        return f"chat {target or 'svc-web'} {sender} {message}".strip()
    if action.kind == "document_share":
        filename = str(action.payload.get("filename", ""))
        return f"document_share {target or 'svc-fileshare'} {filename}".strip()
    if action.kind == "voice":
        return f"voice {target or 'unknown'}".strip()
    return action.kind


def audit_command_for_action(
    action: Action, *, audit_command: str, executed_command: str
) -> str:
    semantic_command = audit_command.strip()
    raw_command = executed_command.strip()
    if action.kind == "shell":
        return raw_command or semantic_command
    return semantic_command or raw_command


def fallback_fingerprint_source(action: Action) -> str:
    target = action_target(action)
    if target:
        return f"{action.kind} {target}"
    return action.kind


def fingerprint_prefix_for_command(command: str, *, token_limit: int) -> str:
    tokens = _unwrap_command_tokens(_command_tokens(command))
    while tokens and _ENV_ASSIGNMENT_RE.match(tokens[0]):
        tokens.pop(0)
    if not tokens:
        cleaned = command.strip().lower()
        return cleaned or "unknown"
    return " ".join(tokens[:token_limit]).lower()


def match_suspicious_patterns(
    command: str, compiled_patterns: tuple[tuple[str, re.Pattern[str]], ...]
) -> tuple[str, ...]:
    if not command:
        return ()
    return tuple(
        pattern for pattern, regex in compiled_patterns if regex.search(command)
    )


def integrity_targets_for_snapshot(
    snapshot: RuntimeSnapshot, config: AuditConfig
) -> dict[str, tuple[str, ...]]:
    if not config.binary_integrity_enabled:
        return {}
    selected_services = set(config.binary_integrity_services)
    chart_services = snapshot.artifacts.chart_values.get("services", {})
    targets: dict[str, tuple[str, ...]] = {}
    for service in sorted(snapshot.world.services, key=lambda item: item.id):
        if selected_services and service.id not in selected_services:
            continue
        payload = chart_services.get(service.id, {})
        unique_paths = tuple(
            dict.fromkeys(
                (
                    *_command_entrypoint_paths(payload.get("command", ())),
                    *_DEFAULT_BINARY_PATHS_BY_KIND.get(service.kind, ()),
                    *config.binary_integrity_paths,
                )
            )
        )
        if unique_paths:
            targets[service.id] = unique_paths[
                : config.binary_integrity_max_paths_per_service
            ]
    return targets


def _compile_patterns(
    patterns: tuple[str, ...],
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern in patterns:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)
        compiled.append((pattern, regex))
    return tuple(compiled)


def _command_tokens(command: str) -> list[str]:
    if not command:
        return []
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _command_name(token: str) -> str:
    return token.rsplit("/", 1)[-1]


def _unwrap_command_tokens(tokens: list[str]) -> list[str]:
    current = list(tokens)
    for _ in range(4):
        unwrapped = _unwrap_command_tokens_once(current)
        if unwrapped is None:
            return current
        current = unwrapped
    return current


def _unwrap_command_tokens_once(tokens: list[str]) -> list[str] | None:
    if not tokens:
        return None
    command_name = _command_name(tokens[0])
    if command_name == "env":
        remainder = list(tokens[1:])
        while remainder:
            token = remainder[0]
            if token == "--":
                remainder = remainder[1:]
                break
            if token.startswith("-") or _ENV_ASSIGNMENT_RE.match(token):
                remainder = remainder[1:]
                continue
            break
        return remainder or None
    if (
        command_name in _SHELL_WRAPPER_NAMES
        and len(tokens) >= 3
        and tokens[1].startswith("-")
        and "c" in tokens[1]
    ):
        inner_tokens = _command_tokens(tokens[2])
        return inner_tokens or None
    return None


def _is_volatile_integrity_path(path: str) -> bool:
    return path.endswith(_VOLATILE_INTEGRITY_SUFFIXES)


def _command_entrypoint_paths(command: Any) -> tuple[str, ...]:
    if isinstance(command, str):
        return (command,) if command.startswith("/") else ()
    if not isinstance(command, (list, tuple)):
        return ()
    return tuple(
        token for token in command if isinstance(token, str) and token.startswith("/")
    )


def _truncate(command: str, limit: int = 512) -> str:
    if len(command) <= limit:
        return command
    return f"{command[: limit - 3]}..."
