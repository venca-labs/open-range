"""Tests for the v1 cyber codegen (realize-as-codegen).

Three concerns:
  1. ``realize_graph`` produces a single Python ``app.py`` artifact that
     compiles cleanly across a sweep of generated graphs.
  2. The generated ``app.py`` actually runs as an HTTP service and
     responds at the public ``/`` route.
  3. Vulnerabilities placed on endpoints have their template body
     inlined — i.e. SQLi UNION SELECT against the realized service
     leaks the flag end-to-end.
"""

from __future__ import annotations

import json
import random
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from openrange.core.builder import build
from openrange.core.graph import Edge, Node, WorldGraph
from openrange.core.manifest import Manifest
from openrange.packs.cyber_webapp_offense_v1.codegen import realize_graph
from openrange.packs.cyber_webapp_offense_v1.priors import PRIORS
from openrange.packs.cyber_webapp_offense_v1.sampling import sample_graph

V1_MANIFEST = {
    "pack": {"id": "cyber.webapp.offense.v1", "source": {"kind": "builtin"}},
    "mode": "simulation",
    "world": {},
}


# ---------------------------------------------------------------------------
# Compile sweep
# ---------------------------------------------------------------------------


def test_realize_graph_compiles_across_seeds() -> None:
    manifest = Manifest.load(V1_MANIFEST)
    for seed in range(8):
        rng = random.Random(seed)
        graph = sample_graph(rng, PRIORS)
        bundle = realize_graph(graph, manifest)
        files = dict(bundle.files())
        assert "app.py" in files
        compile(files["app.py"], f"<seed-{seed}>", "exec")


def test_realize_graph_emits_single_http_entrypoint() -> None:
    manifest = Manifest.load(V1_MANIFEST)
    rng = random.Random(0)
    bundle = realize_graph(sample_graph(rng, PRIORS), manifest)
    assert len(bundle.entrypoints) == 1
    entrypoint = bundle.entrypoints[0]
    assert entrypoint.kind == "http"
    assert entrypoint.metadata["artifact"] == "app.py"


# ---------------------------------------------------------------------------
# Codegen rejects flagless graphs
# ---------------------------------------------------------------------------


def test_realize_rejects_graph_without_flag() -> None:
    manifest = Manifest.load(V1_MANIFEST)
    flagless = WorldGraph(
        nodes=(
            Node(id="svc_x", type="service", attrs={"name": "x", "kind": "web"}),
            Node(
                id="ep_x",
                type="endpoint",
                attrs={"path": "/", "method": "GET", "auth_required": False,
                       "behavior_ref": "web.default"},
            ),
        ),
        edges=(Edge(source="svc_x", relation="exposes", target="ep_x"),),
    )
    with pytest.raises(Exception, match="flag"):
        realize_graph(flagless, manifest)


# ---------------------------------------------------------------------------
# Run the realized app
# ---------------------------------------------------------------------------


def _wait_for_port(port: int, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.05)
    raise TimeoutError(f"port {port} did not open")


def _spawn_app(app_py: Path, log_path: Path) -> tuple[subprocess.Popen[str], int]:
    process = subprocess.Popen(
        [sys.executable, str(app_py), "--port", "0", "--log", str(log_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    if not line:
        process.kill()
        stderr = process.stderr.read() if process.stderr else ""
        raise RuntimeError(f"app did not start: {stderr}")
    data = json.loads(line)
    return process, int(data["port"])


def test_realized_app_serves_root_route(tmp_path: Path) -> None:
    snapshot = build(V1_MANIFEST)
    files = dict(snapshot.runtime.files())
    app_py = tmp_path / "app.py"
    app_py.write_text(files["app.py"], encoding="utf-8")
    log_path = tmp_path / "requests.jsonl"
    process, port = _spawn_app(app_py, log_path)
    try:
        _wait_for_port(port)
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/", timeout=2,
        ) as response:
            assert response.status == 200
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_realized_app_404s_unknown_route(tmp_path: Path) -> None:
    snapshot = build(V1_MANIFEST)
    files = dict(snapshot.runtime.files())
    app_py = tmp_path / "app.py"
    app_py.write_text(files["app.py"], encoding="utf-8")
    log_path = tmp_path / "requests.jsonl"
    process, port = _spawn_app(app_py, log_path)
    try:
        _wait_for_port(port)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/__no_such_route__", timeout=2,
            )
        assert exc_info.value.code == 404
    finally:
        process.terminate()
        process.wait(timeout=5)


# ---------------------------------------------------------------------------
# Vulnerability fires end-to-end
# ---------------------------------------------------------------------------


def _build_with_specific_vuln(kind: str) -> WorldGraph:
    """Build a small graph with a single named vuln on a web endpoint."""
    flag_value = "ORANGE{exfiltrated}"
    nodes = (
        Node(id="net", type="network",
             attrs={"name": "n", "isolation": "bridge", "zone": "dmz"}),
        Node(id="host_web", type="host",
             attrs={"hostname": "w", "os": "linux", "zone": "dmz"}),
        Node(id="svc_web", type="service",
             attrs={"name": "web", "kind": "web", "language": "python",
                    "exposure": "public"}),
        Node(id="ep_web_search", type="endpoint",
             attrs={"path": "/search", "method": "GET",
                    "auth_required": False, "behavior_ref": "web.default"}),
        Node(id="ds_web", type="data_store",
             attrs={"name": "web", "kind": "kv", "engine": "in_memory"}),
        Node(id="rec_flag", type="record",
             attrs={"key": "admin_flag", "fields": {"value": flag_value}}),
        Node(id="secret_flag", type="secret",
             attrs={"kind": "flag", "value_ref": flag_value, "description": ""}),
        Node(id="vuln_x", type="vulnerability",
             attrs={
                 "kind": kind,
                 "family": "code_web",
                 "params": _params_for(kind),
             }),
    )
    edges = (
        Edge(source="svc_web", relation="runs_on", target="host_web"),
        Edge(source="svc_web", relation="connected_to", target="net"),
        Edge(source="svc_web", relation="exposes", target="ep_web_search"),
        Edge(source="svc_web", relation="backed_by", target="ds_web"),
        Edge(source="ds_web", relation="contains", target="rec_flag"),
        Edge(source="rec_flag", relation="holds", target="secret_flag"),
        Edge(source="vuln_x", relation="affects", target="ep_web_search"),
    )
    return WorldGraph(nodes=nodes, edges=edges)


def _params_for(kind: str) -> dict[str, object]:
    if kind == "sql_injection":
        return {
            "target_param": "q",
            "table": "records",
            "leak_column": "value",
        }
    if kind == "broken_authz":
        return {
            "trust_header": "X-User-Role",
            "expected_value": "admin",
            "leak_field": "value",
        }
    return {}


def test_realized_sql_injection_exfiltrates_flag(tmp_path: Path) -> None:
    """SQLi placed on /search leaks the flag via UNION SELECT in the realized app."""
    manifest = Manifest.load(V1_MANIFEST)
    graph = _build_with_specific_vuln("sql_injection")
    bundle = realize_graph(graph, manifest)
    app_py = tmp_path / "app.py"
    app_py.write_text(dict(bundle.files())["app.py"], encoding="utf-8")
    log_path = tmp_path / "requests.jsonl"
    process, port = _spawn_app(app_py, log_path)
    try:
        _wait_for_port(port)
        # benign request: returns no rows (no record with key='public').
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/search?q=public", timeout=2,
        ) as response:
            payload = json.loads(response.read().decode())
        assert "rows" in payload

        # malicious UNION SELECT: leaks the flag via the value column.
        from urllib.parse import quote

        evil = quote("' UNION SELECT value -- ")
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/search?q={evil}", timeout=2,
        ) as response:
            payload = json.loads(response.read().decode())
        rows = payload.get("rows", [])
        assert any("ORANGE{exfiltrated}" in str(row) for row in rows), payload
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_realized_broken_authz_grants_admin_with_forged_header(tmp_path: Path) -> None:
    """Broken-authz placed on /search leaks the secret to admin-headered callers."""
    manifest = Manifest.load(V1_MANIFEST)
    graph = _build_with_specific_vuln("broken_authz")
    bundle = realize_graph(graph, manifest)
    app_py = tmp_path / "app.py"
    app_py.write_text(dict(bundle.files())["app.py"], encoding="utf-8")
    log_path = tmp_path / "requests.jsonl"
    process, port = _spawn_app(app_py, log_path)
    try:
        _wait_for_port(port)
        # broken_authz template reads the trust header from the QUERY (since
        # the vuln template uses the same shape across SQLi/SSRF for parity).
        # No header → 403.
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/search", timeout=2,
            )
        assert exc_info.value.code == 403

        # Forged admin → flag leaked.
        from urllib.parse import quote

        admin_q = quote("admin")
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/search?X-User-Role={admin_q}", timeout=2,
        ) as response:
            payload = json.loads(response.read().decode())
        # The leak_field is "value"; the broken_authz template returns a
        # JSON object {leak_field: secret}. Value comes from state.secrets.
        assert payload.get("value") == "ORANGE{exfiltrated}", payload
    finally:
        process.terminate()
        process.wait(timeout=5)


# ---------------------------------------------------------------------------
# Curriculum patch removes the vuln from generated source
# ---------------------------------------------------------------------------


def test_patched_vuln_removed_from_generated_app() -> None:
    """After ``patch``, the vuln's handler body should no longer be present."""
    from openrange.core.builder import evolve

    s1 = build(V1_MANIFEST)
    kinds_before = sorted(
        {
            n.attrs["kind"]
            for n in s1.world_graph.nodes
            if n.type == "vulnerability"
        },
    )
    s2 = evolve(s1, curriculum={"patch": list(kinds_before)})
    src_after = dict(s2.runtime.files())["app.py"]
    # All vuln handlers gone; only default handlers remain. The SQLi
    # template's distinctive marker is the SQL string interpolation;
    # SSRF's is `urlopen(`; broken_authz's is the trust_header check.
    # None of those should appear in handler bodies after patching.
    assert "state['data_store'].execute(sql)" not in src_after
    assert "_ALLOWLIST" not in src_after
    # Default handler's distinctive marker: the JSON status payload.
    assert '"status": "ok"' in src_after
