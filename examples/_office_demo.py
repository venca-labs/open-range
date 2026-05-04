"""Shared office-demo manifest fragment for the eval examples.

Both ``strands_eval`` and ``codex_eval`` populate the cyber webapp
world with the same six named ``cyber.office_chatter`` NPCs so the
3D dashboard renderer shows a populated office regardless of which
agent harness is running. Extracting it here keeps the two example
scripts in sync.
"""

from __future__ import annotations

OFFICE_STAFF: tuple[str, ...] = (
    "Alice",
    "Bob",
    "Carol",
    "Dave",
    "Eve",
    "Frank",
)


def office_chatter_entries() -> list[dict[str, object]]:
    """Spawn one office chatter per staff name with staggered seeds.

    Cadence at 1.5Hz auto tick: 8 ticks ≈ 5s per NPC. Each chatter
    walks at every cadence boundary; on arrival the dashboard
    orchestrates a coherent opener-and-reply exchange with the
    visited colleague (see ``EXCHANGES`` in ``dashboard.js``). With
    6 chatters that's a visit every ~0.8s globally — busy but not
    spammy.
    """
    return [
        {
            "type": "cyber.office_chatter",
            "config": {
                "name": name,
                "cadence_ticks": 8,
                "walk_probability": 1.0,
                "seed": idx + 1,
            },
        }
        for idx, name in enumerate(OFFICE_STAFF)
    ]
