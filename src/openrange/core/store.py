"""Snapshot persistence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from openrange.core.errors import StoreError
from openrange.core.snapshot import Snapshot


class SnapshotStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def save(self, snapshot: Snapshot) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{snapshot.id}.json"
        path.write_text(
            json.dumps(snapshot.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def load(self, snapshot_id: str) -> Snapshot:
        path = self.root / f"{snapshot_id}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise StoreError(f"snapshot {snapshot_id!r} not found") from exc
        except json.JSONDecodeError as exc:
            raise StoreError(f"snapshot {snapshot_id!r} is not valid JSON") from exc
        if not isinstance(data, Mapping):
            raise StoreError("stored snapshot must be a mapping")
        return Snapshot.from_mapping(cast(Mapping[str, object], data))
