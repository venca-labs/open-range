"""Shared on-disk snapshot path helpers."""

from __future__ import annotations

from pathlib import Path


def snapshot_dir(store_dir: str | Path, snapshot_id: str) -> Path:
    return Path(store_dir) / snapshot_id


def snapshot_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return snapshot_dir(store_dir, snapshot_id) / "snapshot.json"


def metadata_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return snapshot_dir(store_dir, snapshot_id) / "metadata.json"


def world_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return snapshot_dir(store_dir, snapshot_id) / "world.json"


def reference_bundle_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return snapshot_dir(store_dir, snapshot_id) / "reference_bundle.json"


def validator_report_path(store_dir: str | Path, snapshot_id: str) -> Path:
    return snapshot_dir(store_dir, snapshot_id) / "validator_report.json"
