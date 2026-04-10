#!/usr/bin/env python3
"""Run a simulated workday and stream NPC user activity to stdout.

Red and blue do nothing (sleep). The green NPCs carry out their
routine workday — browsing, emailing colleagues, querying databases,
accessing shares — across an 8-hour simulated day.

Modes:
  (default)      Offline — ScriptedGreenScheduler drives all activity.
  --online       Online  — RuntimeNPCAgents drive activity through the
                 ActionOutbox bridge.  Task-driven, memory-aware, with
                 content-rich email payloads (templates).
  --online --model MODEL
                 Online with LLM — agents use the specified model for
                 composing emails, writing replies, and making security
                 decisions.  Falls back to templates on failure.
  --timestamps   Show every individual action with its exact sim_time.

Usage:
    python scripts/npc_activity.py
    python scripts/npc_activity.py --online --timestamps --minutes 120
    python scripts/npc_activity.py --online --model claude-haiku-4-5-20251001
    python scripts/npc_activity.py --minutes 480 --seed 3
"""

from __future__ import annotations

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from open_range._runtime_store import hydrate_runtime_snapshot
from open_range.build_config import OFFLINE_BUILD_CONFIG
from open_range.episode_config import EpisodeConfig
from open_range.pipeline import BuildPipeline
from open_range.resources import load_bundled_manifest
from open_range.runtime import ReferenceDrivenRuntime
from open_range.runtime_types import Action, RuntimeEvent
from open_range.store import FileSnapshotStore
from open_range.world_ir import GreenPersona


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_SVC_LABELS: dict[str, str] = {
    "svc-email":     "email",
    "svc-web":       "web",
    "svc-fileshare": "fileshare",
    "svc-db":        "database",
    "svc-idp":       "identity",
    "svc-siem":      "SIEM",
}


def _action_label(
    event: RuntimeEvent,
    persona_ids: set[str],
    sent_pairs: set[tuple[str, str]] | None = None,
) -> str:
    """Short label describing what the NPC did."""
    target = event.target_entity
    if target in persona_ids:
        if sent_pairs is not None:
            if (target, event.source_entity) in sent_pairs:
                sent_pairs.discard((target, event.source_entity))
                return "read mail"
            sent_pairs.add((event.source_entity, target))
        return "send mail"
    for svc, label in _SVC_LABELS.items():
        if svc in target:
            if "svc-siem" in event.observability_surfaces and svc == "svc-siem":
                return "SIEM alert"
            return label
    # Target is a path or unknown — classify by observability surfaces
    for surf in event.observability_surfaces:
        if surf in _SVC_LABELS:
            return _SVC_LABELS[surf]
    return "web"


def _target_label(event: RuntimeEvent, personas: dict[str, GreenPersona]) -> str:
    t = event.target_entity
    if t in personas:
        p = personas[t]
        prof = p.profile
        name = prof.backstory.full_name if prof and prof.backstory.full_name else p.id
        return f"{name} ({p.role})"
    for svc, label in _SVC_LABELS.items():
        if svc in t:
            return label
    return t or "—"


def _sim_hour(sim_time: float) -> int:
    return 9 + min(int(sim_time) // 60, 8)


def _sim_clock(sim_time: float) -> str:
    total_minutes = int(sim_time)
    hour = 9 + total_minutes // 60
    minute = total_minutes % 60
    return f"{hour:02d}:{minute:02d}"


# ---------------------------------------------------------------------------
# Snapshot loading
# ---------------------------------------------------------------------------


def _load_manifest(source: str | Path | None) -> dict[str, Any]:
    if source is None:
        return load_bundled_manifest("tier1_basic.yaml")
    path = Path(source)
    if path.exists():
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    return load_bundled_manifest(str(source))


def _build_snapshot(manifest: str | Path | None):
    manifest_data = _load_manifest(manifest)
    with TemporaryDirectory(prefix="openrange-npc-") as tmp:
        root = Path(tmp)
        store = FileSnapshotStore(root / "snapshots")
        pipeline = BuildPipeline(store=store)
        candidate = pipeline.build(manifest_data, root / "rendered", OFFLINE_BUILD_CONFIG)
        snapshot = hydrate_runtime_snapshot(
            store, pipeline.admit(candidate, split="train")
        )
    return snapshot, candidate


# ---------------------------------------------------------------------------
# Event printer (shared between offline and online)
# ---------------------------------------------------------------------------


class EventPrinter:
    def __init__(
        self,
        personas: dict[str, GreenPersona],
        timestamps: bool,
        name_w: int,
        role_w: int,
        total_w: int,
        agents: list[Any] | None = None,
    ):
        self.personas = personas
        self.persona_ids = set(personas)
        self.timestamps = timestamps
        self.name_w = name_w
        self.role_w = role_w
        self.total_w = total_w
        self.seen_ids: set[str] = set()
        self.last_hour: int = -1
        self.shown_this_hour: set[str] = set()
        self.ts_seen: set[tuple[str, str, str]] = set()
        self.sent_pairs: set[tuple[str, str]] = set()
        self.action_count = 0
        self._agents = agents or []
        # Per-persona FIFO of submitted action payloads
        self._action_payloads: dict[str, list[dict]] = {}

    def _refresh_payloads(self) -> None:
        """Pull new action payloads from agents' submitted lists."""
        for agent in self._agents:
            pid = agent.persona.id
            if pid not in self._action_payloads:
                self._action_payloads[pid] = []
            for action in agent._submitted:
                self._action_payloads[pid].append(action.payload)
            agent._submitted.clear()

    def _pop_payload(self, persona_id: str) -> dict | None:
        queue = self._action_payloads.get(persona_id)
        if queue:
            return queue.pop(0)
        return None

    @staticmethod
    def _detail_line(payload: dict, act: str) -> str:
        """Build a detail line from the action payload."""
        lines: list[str] = []

        # Message content — chat messages have no subject
        modality = payload.get("modality", "email")
        subj = payload.get("email_subject", "")
        body = payload.get("email_body", "")
        if subj and modality != "chat":
            lines.append(f"         subj: \"{subj}\"")
        if body:
            snippet = body[:70] + ("…" if len(body) > 70 else "")
            lines.append(f"         body: \"{snippet}\"")

        # Reactive branch detail
        branch = payload.get("branch", "")
        if branch == "report_suspicious_activity":
            reported = payload.get("reported_event_type", "unknown")
            target = payload.get("reported_target", "")
            lines.append(f"         [reactive] reported {reported} on {target}")
        elif branch == "npc_chat" and "read" in act and not subj:
            recipient = payload.get("recipient", "")
            if recipient:
                lines.append(f"         [reactive] reading mail from {recipient}")

        # Non-mail task detail
        detail = payload.get("detail", "")
        path = payload.get("path", "")
        if not lines and (detail or path):
            desc = detail or path
            lines.append(f"         ({desc})")

        return "\n".join(lines)

    def process(self, runtime: ReferenceDrivenRuntime) -> None:
        self._refresh_payloads()

        for event in runtime.export_events():
            if event.actor != "green" or event.id in self.seen_ids:
                continue
            self.seen_ids.add(event.id)
            self.action_count += 1

            persona = self.personas.get(event.source_entity)
            if persona is None:
                continue

            payload = self._pop_payload(event.source_entity)
            modality = payload.get("modality", "") if payload else ""

            # Use modality to refine the action label
            act = _action_label(event, self.persona_ids, self.sent_pairs)
            if modality == "chat" and act in ("send mail", "read mail"):
                act = act.replace("mail", "chat")

            tgt = _target_label(event, self.personas)
            tgt_display = "" if tgt == act else tgt
            arrow = "←" if "read" in act else "→"
            suffix = f"  {arrow}  {tgt_display}" if tgt_display else ""

            detail = self._detail_line(payload, act) if payload else ""

            name = f"{persona.id:<{self.name_w}}"
            role = f"[{persona.role}]"

            if self.timestamps:
                clock = _sim_clock(event.time)
                dedup_key = (event.source_entity, clock, act)
                if dedup_key in self.ts_seen:
                    continue
                self.ts_seen.add(dedup_key)
                print(f"  {clock}  {name}  {role:<{self.role_w}}  {act}{suffix}")
                if detail:
                    print(detail)
            else:
                hour = _sim_hour(event.time)
                if hour != self.last_hour:
                    print(f"\n  {'─'*6}  {hour:02d}:00  {'─'*(self.total_w - 14)}")
                    self.last_hour = hour
                    self.shown_this_hour.clear()
                if event.source_entity in self.shown_this_hour:
                    continue
                self.shown_this_hour.add(event.source_entity)
                print(f"    {name}  {role:<{self.role_w}}  {act}{suffix}")
                if detail:
                    print(detail)


# ---------------------------------------------------------------------------
# Header / footer
# ---------------------------------------------------------------------------


def _print_header(
    candidate, personas, minutes, mode_label, name_w, role_w, total_w,
):
    print()
    print("═" * total_w)
    print(f"  NPC Workday Activity Monitor")
    print(f"  World    : {candidate.world.world_id}")
    print(f"  Duration : {minutes:.0f} simulated minutes"
          + (f"  ({minutes/60:.0f}h)" if minutes >= 60 else "")
          + f"  [{mode_label}]")
    print(f"  Personas : {len(personas)}")
    for p in personas.values():
        prof = p.profile
        if prof and prof.backstory.full_name:
            b = prof.backstory
            print(f"             {b.full_name} ({p.id})")
            print(f"               {p.role}, {p.department}  |  {b.location}")
            print(f"               Hours: {b.working_hours}")
            if b.friends:
                print(f"               Friends: {', '.join(b.friends)}")
        else:
            dept = f"[{p.department}]" if p.department else ""
            print(f"             {p.id:<{name_w}} {p.role}  {dept}")
    print("═" * total_w)


def _print_footer(action_count, score, total_w):
    print()
    print("─" * total_w)
    print(f"  {action_count} NPC actions  |  "
          f"sim_time={score.sim_time:.0f}min  |  result={score.winner}")
    print("═" * total_w)
    print()


# ---------------------------------------------------------------------------
# Offline mode (ScriptedGreenScheduler only)
# ---------------------------------------------------------------------------


def _run_offline(snapshot, candidate, minutes, timestamps):
    personas: dict[str, GreenPersona] = {
        p.id: p for p in snapshot.world.green_personas
    }
    name_w = max(len(pid) for pid in personas) + 2
    role_w = max(len(p.role) for p in personas.values()) + 2
    total_w = name_w + role_w + 32

    cfg = EpisodeConfig(
        mode="joint_pool", scheduler_mode="async",
        green_enabled=True, green_routine_enabled=True,
        green_branch_enabled=False, green_profile="high",
        opponent_red="none", opponent_blue="none",
        episode_horizon_minutes=minutes,
        telemetry_delay_enabled=False, npc_mode="offline",
    )
    sleep_red  = Action(actor_id="red",  role="red",  kind="sleep", payload={})
    sleep_blue = Action(actor_id="blue", role="blue", kind="sleep", payload={})

    runtime = ReferenceDrivenRuntime()
    printer = EventPrinter(personas, timestamps, name_w, role_w, total_w)

    _print_header(candidate, personas, minutes, "offline", name_w, role_w, total_w)

    runtime.reset(snapshot, cfg)
    printer.process(runtime)

    while not runtime.state().done:
        try:
            decision = runtime.next_decision()
        except RuntimeError:
            break
        action = sleep_red if decision.actor == "red" else sleep_blue
        runtime.act(decision.actor, action)
        printer.process(runtime)

    score = runtime.score()
    runtime.close()
    _print_footer(printer.action_count, score, total_w)


# ---------------------------------------------------------------------------
# Online mode (RuntimeNPCAgents through ActionOutbox)
# ---------------------------------------------------------------------------


def _run_online(snapshot, candidate, minutes, timestamps, model: str = ""):
    import asyncio
    from open_range.builder.npc.identity import generate_profiles
    from open_range.builder.npc.outbox import ActionOutbox, MailStore, SimClock
    from open_range.builder.npc.runtime_agent import RuntimeNPCAgent
    from open_range.builder.npc.tasks import generate_tasks
    from open_range.green import ScriptedGreenScheduler

    # Enrich personas with profiles (names, friends, personality) if missing
    all_personas = list(snapshot.world.green_personas)
    enriched: list[GreenPersona] = []
    needs_profiles = [p for p in all_personas if p.profile is None]
    if needs_profiles:
        persona_dicts = [{"id": p.id, "role": p.role, "department": p.department}
                         for p in needs_profiles]
        profiles = generate_profiles(persona_dicts)
        profile_map = {needs_profiles[i].id: profiles[i] for i in range(len(profiles))}
        for p in all_personas:
            if p.id in profile_map:
                enriched.append(p.model_copy(update={"profile": profile_map[p.id]}))
            else:
                enriched.append(p)
    else:
        enriched = all_personas

    personas: dict[str, GreenPersona] = {p.id: p for p in enriched}
    name_w = max(len(pid) for pid in personas) + 2
    role_w = max(len(p.role) for p in personas.values()) + 2
    total_w = name_w + role_w + 32

    # Wire the bridge
    outbox = ActionOutbox(max_size=500)
    clock = SimClock()
    mail_store = MailStore()
    scheduler = ScriptedGreenScheduler(action_outbox=outbox, sim_clock=clock)
    runtime = ReferenceDrivenRuntime(green_scheduler=scheduler)

    cfg = EpisodeConfig(
        mode="joint_pool", scheduler_mode="async",
        green_enabled=True,
        green_routine_enabled=False,  # agents handle routines via outbox
        green_branch_enabled=False,
        green_profile="high",
        opponent_red="none", opponent_blue="none",
        episode_horizon_minutes=minutes,
        telemetry_delay_enabled=False, npc_mode="online",
    )
    sleep_red  = Action(actor_id="red",  role="red",  kind="sleep", payload={})
    sleep_blue = Action(actor_id="blue", role="blue", kind="sleep", payload={})

    runtime.reset(snapshot, cfg)

    # Create agents — they share memory and inboxes with the scheduler
    agents: list[RuntimeNPCAgent] = []
    for persona in enriched:
        tasks = generate_tasks(persona, enriched)
        agent = RuntimeNPCAgent(
            persona,
            memory=scheduler._memory_streams[persona.id],
            outbox=outbox,
            inbox=scheduler._event_inboxes[persona.id],
            clock=clock,
            tasks=tasks,
            colleagues=enriched,
            mail_store=mail_store,
            model=model,
        )
        agents.append(agent)

    printer = EventPrinter(
        personas, timestamps, name_w, role_w, total_w, agents=agents,
    )
    mode_tag = f"online, model={model}" if model else "online"
    _print_header(candidate, personas, minutes, mode_tag, name_w, role_w, total_w)
    printer.process(runtime)

    if model:
        # Async loop — agents use LLM for email composition and reactions
        async def _drive_async():
            while not runtime.state().done:
                for agent in agents:
                    await agent._process_inbox_async()
                    await agent._maybe_submit_next_async()
                try:
                    decision = runtime.next_decision()
                except RuntimeError:
                    break
                action = sleep_red if decision.actor == "red" else sleep_blue
                runtime.act(decision.actor, action)
                printer.process(runtime)

        asyncio.run(_drive_async())
    else:
        # Sync loop — template content only, fast and deterministic
        while not runtime.state().done:
            for agent in agents:
                agent._process_inbox()
                agent._maybe_submit_next()
            try:
                decision = runtime.next_decision()
            except RuntimeError:
                break
            action = sleep_red if decision.actor == "red" else sleep_blue
            runtime.act(decision.actor, action)
            printer.process(runtime)

    score = runtime.score()
    runtime.close()

    # Show agent memory stats
    print()
    for agent in agents:
        n_mem = len(agent.memory)
        n_act = agent._actions_submitted
        print(f"  {agent.persona.id:<{name_w}}  {n_act} actions submitted"
              f"  |  {n_mem} memories")

    _print_footer(printer.action_count, score, total_w)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run(
    *,
    manifest: str | Path | None = None,
    seed: int = 42,
    minutes: float = 480.0,
    timestamps: bool = False,
    online: bool = False,
    model: str = "",
) -> None:
    snapshot, candidate = _build_snapshot(manifest)
    if online:
        _run_online(snapshot, candidate, minutes, timestamps, model=model)
    else:
        _run_offline(snapshot, candidate, minutes, timestamps)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stream NPC workday activity for one OpenRange episode."
    )
    parser.add_argument("--manifest", default=None,
                        help="Bundled manifest name or path to a YAML manifest.")
    parser.add_argument("--minutes", type=float, default=480.0,
                        help="Simulated duration in minutes (default: 480 = 8h day).")
    parser.add_argument("--seed", type=int, default=42,
                        help="Episode seed (default: 42).")
    parser.add_argument("--timestamps", action="store_true",
                        help="Print every individual action with its exact sim_time.")
    parser.add_argument("--online", action="store_true",
                        help="Use RuntimeNPCAgents (task-driven, memory-aware).")
    parser.add_argument("--model", default="",
                        help="LLM model for email generation (e.g. claude-haiku-4-5-20251001). "
                             "Requires --online. Without this, templates are used.")
    args = parser.parse_args()
    run(manifest=args.manifest, seed=args.seed, minutes=args.minutes,
        timestamps=args.timestamps, online=args.online, model=args.model)


if __name__ == "__main__":
    main()
