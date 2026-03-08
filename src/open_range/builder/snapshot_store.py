"""Snapshot persistence -- save, list, and select validated snapshots.

Validated snapshots are stored as frozen JSON under ``snapshots/<id>/spec.json``.
The store supports selection strategies for ``reset()`` to draw from a pool of
pre-validated snapshots rather than generating on-demand.
"""

from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from open_range.protocols import SnapshotSpec

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StoredSnapshot:
    """A frozen snapshot plus its persisted identifier."""

    snapshot_id: str
    snapshot: SnapshotSpec


class SnapshotStore:
    """Persist and retrieve validated snapshot specs."""

    def __init__(self, store_dir: str = "snapshots") -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    async def store(self, snapshot: SnapshotSpec, snapshot_id: str | None = None) -> str:
        """Save a validated snapshot to disk.

        Args:
            snapshot: The validated snapshot spec.
            snapshot_id: Optional explicit ID. Generated from topology if absent.

        Returns:
            The snapshot ID string.
        """
        if snapshot_id is None:
            hosts = snapshot.topology.get("hosts", [])
            vuln_types = [v.type for v in snapshot.truth_graph.vulns]
            snapshot_id = (
                f"snap_{'_'.join(vuln_types[:3])}"
                f"_{int(time.time())}"
            )

        snap_dir = self.store_dir / snapshot_id
        snap_dir.mkdir(parents=True, exist_ok=True)

        spec_path = snap_dir / "spec.json"
        spec_path.write_text(
            snapshot.model_dump_json(indent=2),
            encoding="utf-8",
        )

        # Write metadata sidecar for fast listing
        meta = {
            "snapshot_id": snapshot_id,
            "vuln_classes": [v.type for v in snapshot.truth_graph.vulns],
            "golden_path_steps": len(snapshot.golden_path),
            "flag_count": len(snapshot.flags),
            "npc_count": len(snapshot.npc_personas),
            "has_compose": bool(snapshot.compose),
            "stored_at": time.time(),
        }
        meta_path = snap_dir / "metadata.json"
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        logger.info("Stored snapshot %s at %s", snapshot_id, snap_dir)
        return snapshot_id

    async def select(self, strategy: str = "latest") -> SnapshotSpec:
        """Select a snapshot from the store.

        Args:
            strategy: Selection strategy.
                - ``"latest"``: most recently stored snapshot
                - ``"random"``: uniformly random

        Returns:
            The selected SnapshotSpec.

        Raises:
            FileNotFoundError: If the store is empty.
        """
        return (await self.select_entry(strategy=strategy)).snapshot

    async def select_entry(self, strategy: str = "latest") -> StoredSnapshot:
        """Select a snapshot plus its persisted ID."""
        spec_files = sorted(self.store_dir.glob("*/spec.json"))
        if not spec_files:
            raise FileNotFoundError(
                f"No snapshots in store: {self.store_dir}"
            )

        if strategy == "random":
            chosen = random.choice(spec_files)
        else:  # latest -- sort by parent dir mtime
            chosen = max(spec_files, key=lambda p: p.stat().st_mtime)

        raw = json.loads(chosen.read_text(encoding="utf-8"))
        return StoredSnapshot(
            snapshot_id=chosen.parent.name,
            snapshot=SnapshotSpec.model_validate(raw),
        )

    async def list_snapshots(self) -> list[dict[str, Any]]:
        """List all snapshots with their metadata.

        Returns:
            List of metadata dicts, sorted by stored_at descending.
        """
        results: list[dict[str, Any]] = []
        for meta_path in self.store_dir.glob("*/metadata.json"):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                results.append(meta)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping corrupt metadata: %s (%s)", meta_path, exc)

        results.sort(key=lambda m: m.get("stored_at", 0), reverse=True)
        return results

    async def get(self, snapshot_id: str) -> SnapshotSpec:
        """Load a specific snapshot by ID.

        Raises:
            FileNotFoundError: If the snapshot does not exist.
        """
        spec_path = self.store_dir / snapshot_id / "spec.json"
        if not spec_path.exists():
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id}")
        raw = json.loads(spec_path.read_text(encoding="utf-8"))
        return SnapshotSpec.model_validate(raw)

    async def get_entry(self, snapshot_id: str) -> StoredSnapshot:
        """Load a specific snapshot plus its ID."""
        return StoredSnapshot(
            snapshot_id=snapshot_id,
            snapshot=await self.get(snapshot_id),
        )
