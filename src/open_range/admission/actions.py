"""Shared reference-action helpers for admission and runtime replay."""

from __future__ import annotations

from open_range.admission.models import ReferenceAction
from open_range.catalog.probes import runtime_payload_for_reference_action
from open_range.runtime_types import Action


def runtime_action(actor: str, step: ReferenceAction) -> Action:
    payload = runtime_payload_for_reference_action(
        actor,
        step.kind,
        target=step.target,
        payload=step.payload,
    )
    return Action(actor_id=actor, role=actor, kind=step.kind, payload=payload)
