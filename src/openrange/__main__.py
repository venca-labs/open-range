"""OpenRange CLI."""

from __future__ import annotations

import argparse
import json
import webbrowser
from pathlib import Path

from openrange.core import Snapshot, SnapshotStore, build
from openrange.dashboard import DashboardHTTPServer, DashboardView
from openrange.llm import CodexBackend


def main() -> None:
    parser = argparse.ArgumentParser(prog="openrange")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("manifest", type=Path)
    build_parser.add_argument("--output", type=Path)
    build_parser.add_argument("--prompt", default="")

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("snapshot", type=Path)

    dashboard_parser = subparsers.add_parser("dashboard")
    dashboard_parser.add_argument("--store-dir", type=Path, default=Path("snapshots"))
    dashboard_parser.add_argument("--snapshot-id")
    dashboard_parser.add_argument(
        "--run-root",
        type=Path,
        help="Open a previous run directory containing dashboard artifacts",
    )
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=8000)
    dashboard_parser.add_argument("--no-browser", action="store_true")

    args = parser.parse_args()
    if args.command == "build":
        snapshot = build(
            args.manifest,
            prompt=args.prompt,
            llm=CodexBackend(),
        )
        payload = snapshot.as_dict()
        if args.output is not None:
            path = SnapshotStore(args.output).save(snapshot)
            print(path)
        else:
            print(json.dumps(payload, sort_keys=True))
        return
    if args.command == "dashboard":
        snapshot_id = args.snapshot_id or latest_snapshot_id(args.store_dir)
        dashboard_snapshot: Snapshot | None = None
        if args.run_root is None and snapshot_id is not None:
            dashboard_snapshot = SnapshotStore(args.store_dir).load(snapshot_id)
        event_log_path = None
        state_path = None
        reset_artifacts = True
        if args.run_root is not None:
            event_log_path = args.run_root / "dashboard.events.jsonl"
            state_path = args.run_root / "dashboard.json"
            if not event_log_path.exists() or not state_path.exists():
                parser.error(
                    "--run-root must contain dashboard.events.jsonl and dashboard.json",
                )
            reset_artifacts = False
        server = DashboardHTTPServer(
            (args.host, args.port),
            DashboardView(
                dashboard_snapshot,
                event_log_path=event_log_path,
                state_path=state_path,
                reset_artifacts=reset_artifacts,
            ),
        )
        host = str(server.server_address[0])
        url = f"http://{host}:{server.server_address[1]}"
        print(url, flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.view.bridge.close()
            server.server_close()
        return
    data = json.loads(args.snapshot.read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                "id": data["id"],
                "tasks": [task["id"] for task in data["tasks"]],
                "lineage": [node["id"] for node in data["lineage"]],
            },
            sort_keys=True,
        ),
    )


def latest_snapshot_id(store_dir: Path) -> str | None:
    snapshots = sorted(store_dir.glob("*.json"))
    if not snapshots:
        return None
    return snapshots[-1].stem
