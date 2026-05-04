"""Shared office-demo manifest fragment for the eval examples.

Both ``strands_eval`` and ``codex_eval`` populate the cyber webapp
world with the same six named ``cyber.office_chatter`` NPCs so the
3D dashboard renderer shows a populated office regardless of which
agent harness is running. Extracting it here keeps the two example
scripts in sync and avoids copy-pasted phrase pools drifting.
"""

from __future__ import annotations

OFFICE_STAFF: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Alice",
        (
            "morning",
            "did the prod deploy go out?",
            "ping me when you've got a sec",
            "merge conflict on the auth branch",
        ),
    ),
    (
        "Bob",
        (
            "coffee?",
            "i'm gonna grab lunch",
            "anyone seen the wifi go down?",
            "back-to-back today",
        ),
    ),
    (
        "Carol",
        (
            "standup in five",
            "i'll handle the rotation",
            "is the dashboard up for you?",
            "found a flaky test",
        ),
    ),
    (
        "Dave",
        (
            "wfh tomorrow",
            "anyone got bandwidth for review?",
            "build is red on main",
            "rolled back the migration",
        ),
    ),
    (
        "Eve",
        (
            "this query is slow on prod",
            "needs another pair of eyes",
            "shipped the patch",
            "okay heading to the kitchen",
        ),
    ),
    (
        "Frank",
        (
            "deploy paused — talk to ops",
            "incident channel is quiet",
            "tickets cleared for the week",
            "anyone know the wifi password?",
        ),
    ),
)


def office_chatter_entries() -> list[dict[str, object]]:
    """Build one ``cyber.office_chatter`` NPC entry per office staff member.

    Seeds are stable per name (1..N) so a fresh build re-plays the
    same conversational rhythm — useful for matching screen
    recordings across re-runs.
    """
    # Cadence at 1.5Hz auto tick: 8 ticks ≈ 5s per NPC, staggered by
    # seed. ``walk_probability=0.8`` makes 4 of 5 acts a walk, so the
    # floor is mostly people in motion with occasional speech bubbles.
    # Per-NPC: walk every ~6s, speak every ~25s.
    # Globally (6 NPCs): walk every ~1s, speak every ~4s.
    return [
        {
            "type": "cyber.office_chatter",
            "config": {
                "name": name,
                "lines": list(lines),
                "cadence_ticks": 8,
                "walk_probability": 0.8,
                "seed": idx + 1,
            },
        }
        for idx, (name, lines) in enumerate(OFFICE_STAFF)
    ]
