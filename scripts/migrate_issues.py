#!/usr/bin/env python3
"""Migrate issues from open-cybernauts/open-range to venca-labs/open-range.

Uses the `gh` CLI which must be authenticated. Handles:
  - label creation (idempotent)
  - full issue body + metadata migration
  - state preservation (open/closed)
  - provenance footer linking back to original issue

Usage:
    python scripts/migrate_issues.py [--dry-run]
"""

import json
import subprocess
import sys
import time

SRC = "open-cybernauts/open-range"
DST = "venca-labs/open-range"

CUSTOM_LABELS = {
    "phase-1": {"color": "0E8A16", "desc": "Phase 1 work"},
    "phase-2": {"color": "1D76DB", "desc": "Phase 2 work"},
    "phase-3": {"color": "5319E7", "desc": "Phase 3 work"},
    "phase-4": {"color": "B60205", "desc": "Phase 4 work"},
    "in-progress": {"color": "FBCA04", "desc": "Currently being worked on"},
    "runtime": {"color": "D93F0B", "desc": "Runtime module"},
    "npc": {"color": "0075CA", "desc": "NPC / green user"},
    "admission": {"color": "E4E669", "desc": "Admission pipeline"},
    "infra": {"color": "C5DEF5", "desc": "Infrastructure"},
    "ui": {"color": "BFD4F2", "desc": "UI"},
    "training": {"color": "F9D0C4", "desc": "Training pipeline"},
}


def gh(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if check and result.returncode != 0:
        print(f"  [gh error] {' '.join(args)}: {result.stderr.strip()}")
        return ""
    return result.stdout.strip()


def ensure_labels(dry_run: bool) -> None:
    print("--- Ensuring labels on target repo ---")
    existing_raw = gh(
        "label", "list", "--repo", DST, "--json", "name", "--limit", "100"
    )
    existing = (
        {lbl["name"] for lbl in json.loads(existing_raw)} if existing_raw else set()
    )

    for name, meta in CUSTOM_LABELS.items():
        if name in existing:
            print(f"  [skip] label '{name}' already exists")
            continue
        if dry_run:
            print(f"  [dry-run] would create label '{name}'")
            continue
        gh(
            "label",
            "create",
            name,
            "--repo",
            DST,
            "--color",
            meta["color"],
            "--description",
            meta["desc"],
            check=False,
        )
        print(f"  [created] label '{name}'")
        time.sleep(0.5)


def fetch_all_issues() -> list[dict]:
    print(f"--- Fetching all issues from {SRC} ---")
    raw = gh(
        "issue",
        "list",
        "--repo",
        SRC,
        "--state",
        "all",
        "--limit",
        "500",
        "--json",
        "number,title,body,labels,state,author",
    )
    issues = json.loads(raw) if raw else []
    issues.sort(key=lambda i: i["number"])
    print(f"  Found {len(issues)} issues")
    return issues


def migrate_issues(issues: list[dict], dry_run: bool) -> None:
    # Fetch already-migrated titles to avoid duplicates
    existing_raw = gh(
        "issue",
        "list",
        "--repo",
        DST,
        "--state",
        "all",
        "--limit",
        "500",
        "--json",
        "title",
    )
    existing_titles = set()
    if existing_raw:
        existing_titles = {i["title"] for i in json.loads(existing_raw)}
    print(f"  {len(existing_titles)} issues already exist in target")

    print(f"\n--- Migrating {len(issues)} issues to {DST} ---")
    for i, issue in enumerate(issues):
        num = issue["number"]
        title = issue["title"]
        author = issue.get("author", {}).get("login", "unknown")
        labels = [lbl["name"] for lbl in issue.get("labels", [])]
        state = issue.get("state", "OPEN")
        body = issue.get("body", "") or ""

        # Add provenance footer
        footer = (
            f"\n\n---\n"
            f"_Migrated from [{SRC}#{num}](https://github.com/{SRC}/issues/{num})_  \n"
            f"_Original author: @{author}_"
        )
        full_body = body + footer

        if dry_run:
            label_str = ", ".join(labels) if labels else "none"
            skip = " [SKIP]" if title in existing_titles else ""
            print(f"  [dry-run] #{num}: {title} ({state}, labels: {label_str}){skip}")
            continue

        if title in existing_titles:
            print(f"  [{i + 1}/{len(issues)}] #{num} SKIP (already exists): {title}")
            continue

        # Create the issue
        cmd = [
            "issue",
            "create",
            "--repo",
            DST,
            "--title",
            title,
            "--body",
            full_body,
        ]
        for label in labels:
            cmd.extend(["--label", label])

        result = gh(*cmd, check=False)
        if result:
            new_url = result
            print(f"  [{i + 1}/{len(issues)}] #{num} -> {new_url}")
        else:
            print(f"  [{i + 1}/{len(issues)}] #{num} FAILED: {title}")
            time.sleep(1)
            continue

        # Close if original was closed
        if state == "CLOSED" and result:
            new_num = result.rstrip("/").split("/")[-1]
            gh("issue", "close", new_num, "--repo", DST, check=False)
            print(f"    -> closed #{new_num}")

        # Rate limit courtesy
        time.sleep(0.8)


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    if dry_run:
        print("=== DRY RUN MODE ===\n")

    ensure_labels(dry_run)
    issues = fetch_all_issues()
    migrate_issues(issues, dry_run)

    print("\n--- Migration complete ---")


if __name__ == "__main__":
    main()
