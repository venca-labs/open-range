#!/usr/bin/env python3
"""Migrate PRs from open-cybernauts/open-range to venca-labs/open-range.

- Open PRs: recreated as real PRs (branches must already exist on target)
- Merged/closed PRs: archived as issues with 'migrated-pr' label

Usage:
    python scripts/migrate_prs.py [--dry-run]
"""

import json
import subprocess
import sys
import time

SRC = "open-cybernauts/open-range"
DST = "venca-labs/open-range"


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


def ensure_label(dry_run: bool) -> None:
    existing_raw = gh(
        "label", "list", "--repo", DST, "--json", "name", "--limit", "100"
    )
    existing = (
        {lbl["name"] for lbl in json.loads(existing_raw)} if existing_raw else set()
    )
    if "migrated-pr" not in existing:
        if dry_run:
            print("  [dry-run] would create 'migrated-pr' label")
        else:
            gh(
                "label",
                "create",
                "migrated-pr",
                "--repo",
                DST,
                "--color",
                "6F42C1",
                "--description",
                "Archived PR migrated from open-cybernauts",
                check=False,
            )
            print("  [created] 'migrated-pr' label")
            time.sleep(0.5)


def fetch_all_prs() -> list[dict]:
    print(f"--- Fetching all PRs from {SRC} ---")
    raw = gh(
        "pr",
        "list",
        "--repo",
        SRC,
        "--state",
        "all",
        "--limit",
        "500",
        "--json",
        "number,title,body,state,headRefName,baseRefName,author,labels",
    )
    prs = json.loads(raw) if raw else []
    prs.sort(key=lambda p: p["number"])
    print(f"  Found {len(prs)} PRs")
    return prs


def migrate_prs(prs: list[dict], dry_run: bool) -> None:
    # Dedup check
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

    # Also check existing PRs on target
    existing_pr_raw = gh(
        "pr",
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
    if existing_pr_raw:
        existing_titles |= {p["title"] for p in json.loads(existing_pr_raw)}

    print(f"  {len(existing_titles)} titles already exist in target")
    print(f"\n--- Migrating {len(prs)} PRs to {DST} ---")

    for i, pr in enumerate(prs):
        num = pr["number"]
        title = pr["title"]
        state = pr["state"]
        head = pr["headRefName"]
        base = pr["baseRefName"]
        author = pr.get("author", {}).get("login", "unknown")
        body = pr.get("body", "") or ""

        footer = (
            f"\n\n---\n"
            f"_Migrated from [{SRC}#{num}](https://github.com/{SRC}/pull/{num})_  \n"
            f"_Original author: @{author} | State: {state} | `{head}` → `{base}`_"
        )
        full_body = body + footer

        if title in existing_titles:
            tag = "[dry-run] " if dry_run else ""
            print(f"  {tag}[{i + 1}/{len(prs)}] #{num} SKIP: {title}")
            continue

        if state == "OPEN":
            # Create a real PR on the target
            if dry_run:
                print(f"  [dry-run] #{num}: CREATE PR '{title}' ({head} -> {base})")
                continue
            result = gh(
                "pr",
                "create",
                "--repo",
                DST,
                "--title",
                title,
                "--body",
                full_body,
                "--head",
                head,
                "--base",
                base,
                check=False,
            )
            if result:
                print(f"  [{i + 1}/{len(prs)}] #{num} -> PR {result}")
            else:
                # Fallback: archive as issue if branch doesn't exist
                print(
                    f"  [{i + 1}/{len(prs)}] #{num} PR creation failed, archiving as issue"
                )
                archive_title = f"[PR] {title}"
                result = gh(
                    "issue",
                    "create",
                    "--repo",
                    DST,
                    "--title",
                    archive_title,
                    "--body",
                    full_body,
                    "--label",
                    "migrated-pr",
                    check=False,
                )
                if result:
                    print(f"    -> archived as {result}")
        else:
            # Merged or closed: archive as issue
            archive_title = f"[PR] {title}"
            if archive_title in existing_titles:
                print(f"  [{i + 1}/{len(prs)}] #{num} SKIP: {archive_title}")
                continue
            if dry_run:
                print(f"  [dry-run] #{num}: ARCHIVE '{archive_title}' ({state})")
                continue
            result = gh(
                "issue",
                "create",
                "--repo",
                DST,
                "--title",
                archive_title,
                "--body",
                full_body,
                "--label",
                "migrated-pr",
                check=False,
            )
            if result:
                new_num = result.rstrip("/").split("/")[-1]
                # Close the archived issue since the PR is done
                gh("issue", "close", new_num, "--repo", DST, check=False)
                print(f"  [{i + 1}/{len(prs)}] #{num} -> {result} (closed)")
            else:
                print(f"  [{i + 1}/{len(prs)}] #{num} FAILED: {title}")

        time.sleep(0.8)


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    if dry_run:
        print("=== DRY RUN MODE ===\n")

    ensure_label(dry_run)
    prs = fetch_all_prs()
    migrate_prs(prs, dry_run)
    print("\n--- PR migration complete ---")


if __name__ == "__main__":
    main()
