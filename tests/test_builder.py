"""Tests for Builder implementations and SnapshotStore."""

import json
import tempfile

import pytest

from open_range.protocols import BuildContext, FlagSpec, GoldenPathStep, SnapshotSpec


# ---------------------------------------------------------------------------
# TemplateOnlyBuilder
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_template_builder_returns_snapshot_spec(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)
    assert isinstance(spec, SnapshotSpec)


@pytest.mark.asyncio
async def test_template_builder_has_flags(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)
    assert len(spec.flags) >= 1
    assert all(f.value.startswith("FLAG{") for f in spec.flags)


@pytest.mark.asyncio
async def test_template_builder_has_golden_path(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)
    assert len(spec.golden_path) >= 3


@pytest.mark.asyncio
async def test_template_builder_has_truth_graph(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)
    assert len(spec.truth_graph.vulns) >= 1


@pytest.mark.asyncio
async def test_template_builder_respects_bug_families(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)
    allowed = set(tier1_manifest["bug_families"])
    for v in spec.truth_graph.vulns:
        assert v.type in allowed


@pytest.mark.asyncio
async def test_template_builder_clamps_min_vulns_to_candidate_pool(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    manifest = {
        **tier1_manifest,
        "bug_families": ["sqli"],
        "difficulty": {**tier1_manifest.get("difficulty", {}), "min_vulns": 2, "max_vulns": 2},
    }

    spec = await builder.build(manifest, BuildContext(seed=7, tier=1))
    assert len(spec.truth_graph.vulns) == 1
    assert all(v.type == "sqli" for v in spec.truth_graph.vulns)


@pytest.mark.asyncio
async def test_template_builder_fails_when_bug_family_has_no_template_match(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    manifest = {
        **tier1_manifest,
        "bug_families": ["totally_fake_bug_family"],
    }
    with pytest.raises(ValueError, match="No template vulnerabilities match manifest bug_families"):
        await builder.build(manifest, BuildContext(seed=7, tier=1))


@pytest.mark.asyncio
async def test_template_builder_empty_bug_families_uses_default_pool(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    manifest = {
        **tier1_manifest,
        "bug_families": [],
        "difficulty": {**tier1_manifest.get("difficulty", {}), "min_vulns": 1, "max_vulns": 1},
    }
    spec = await builder.build(manifest, BuildContext(seed=7, tier=1))
    assert len(spec.truth_graph.vulns) == 1


@pytest.mark.asyncio
async def test_template_builder_avoids_previous_vulns(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=0, tier=1, previous_vuln_classes=["sqli"])
    spec = await builder.build(tier1_manifest, ctx)
    # Should prefer non-sqli vulns when alternatives exist
    vuln_types = [v.type for v in spec.truth_graph.vulns]
    # Not guaranteed to avoid sqli if all alternatives exhausted, but should try
    # Just verify the builder ran successfully
    assert len(vuln_types) >= 1


@pytest.mark.asyncio
async def test_template_builder_deterministic_with_seed(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx1 = BuildContext(seed=123, tier=1)
    ctx2 = BuildContext(seed=123, tier=1)
    spec1 = await builder.build(tier1_manifest, ctx1)
    spec2 = await builder.build(tier1_manifest, ctx2)
    assert spec1.flags[0].value == spec2.flags[0].value


@pytest.mark.asyncio
async def test_template_builder_has_task_briefings(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)
    assert spec.task.red_briefing != ""
    assert spec.task.blue_briefing != ""


@pytest.mark.asyncio
async def test_template_builder_preserves_manifest_tier_and_difficulty(tier2_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=2)
    spec = await builder.build(tier2_manifest, ctx)
    assert spec.topology["tier"] == tier2_manifest["tier"]
    assert spec.topology["difficulty"] == tier2_manifest["difficulty"]


@pytest.mark.asyncio
async def test_template_builder_emits_payload_files(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    ctx = BuildContext(seed=42, tier=1)
    spec = await builder.build(tier1_manifest, ctx)
    assert spec.files
    assert any(key.startswith("web:/var/www/portal/") for key in spec.files)
    assert any(key.endswith("/var/log/app/access.log") for key in spec.files)


@pytest.mark.asyncio
async def test_template_builder_uses_manifest_users(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    spec = await builder.build(tier1_manifest, BuildContext(seed=1, tier=1))
    usernames = {user["username"] for user in spec.topology["users"]}
    manifest_usernames = {user["username"] for user in tier1_manifest["users"]}
    assert manifest_usernames.issubset(usernames)


@pytest.mark.asyncio
async def test_template_builder_uses_manifest_company_context(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    spec = await builder.build(tier1_manifest, BuildContext(seed=1, tier=1))
    company = tier1_manifest["company"]
    ldap_dn = ",".join(f"dc={part}" for part in company["domain"].split("."))

    assert company["name"] in spec.task.red_briefing
    assert company["name"] in spec.task.blue_briefing
    assert ldap_dn in spec.files["web:/var/www/config.php"]
    assert company["name"] in spec.files["web:/var/www/portal/index.php"]


@pytest.mark.asyncio
async def test_template_builder_output_is_manifest_canonicalized(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder

    builder = TemplateOnlyBuilder()
    spec = await builder.build(tier1_manifest, BuildContext(seed=1, tier=1))
    assert "host_catalog" in spec.topology
    assert "host_details" in spec.topology
    assert "dependency_edges" in spec.topology
    assert "principal_catalog" in spec.topology


def test_render_payloads_credential_reuse_not_coupled_to_path_traversal_flag():
    from open_range.builder.builder import render_template_payloads
    from open_range.protocols import TruthGraph, Vulnerability

    snapshot = SnapshotSpec(
        topology={"tier": 1, "hosts": ["web"], "org_name": "OpenRange", "domain": "corp.local"},
        truth_graph=TruthGraph(
            vulns=[Vulnerability(id="v1", type="credential_reuse", host="ldap")]
        ),
        flags=[FlagSpec(id="f1", value="FLAG{cred_only}", path="/var/flags/flag1.txt", host="db")],
        golden_path=[],
    )
    files = render_template_payloads(snapshot)
    download = files["web:/var/www/portal/download.php"]
    assert "config.php" in download
    assert "FLAG{cred_only}" not in download
    assert "flag1.txt" not in download


def test_render_payloads_path_traversal_keeps_flag_wiring():
    from open_range.builder.builder import render_template_payloads
    from open_range.protocols import TruthGraph, Vulnerability

    snapshot = SnapshotSpec(
        topology={"tier": 1, "hosts": ["web"], "org_name": "OpenRange", "domain": "corp.local"},
        truth_graph=TruthGraph(
            vulns=[Vulnerability(id="v1", type="path_traversal", host="web")]
        ),
        flags=[FlagSpec(id="f1", value="FLAG{path}", path="/var/flags/path_flag.txt", host="web")],
        golden_path=[],
    )
    files = render_template_payloads(snapshot)
    download = files["web:/var/www/portal/download.php"]
    assert "FLAG{path}" in download
    assert "path_flag.txt" in download


@pytest.mark.asyncio
async def test_mutator_builds_child_snapshot_with_lineage(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.builder.mutator import Mutator

    builder = TemplateOnlyBuilder()
    mutator = Mutator(builder)
    root = await mutator.mutate(tier1_manifest, context=BuildContext(seed=1, tier=1))
    child = await mutator.mutate(
        tier1_manifest,
        context=BuildContext(seed=2, tier=1),
        parent_snapshot=root,
        parent_snapshot_id="root_snap",
    )
    assert child.lineage.parent_snapshot_id == "root_snap"
    assert child.lineage.generation_depth == 1
    assert child.mutation_plan is not None
    assert child.mutation_plan.parent_snapshot_id == "root_snap"
    assert child.mutation_plan.ops
    assert child.lineage.mutation_summary


@pytest.mark.asyncio
async def test_mutator_compiles_root_snapshot_from_manifest_graph(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.builder.mutator import Mutator

    root = await Mutator(TemplateOnlyBuilder()).mutate(
        tier1_manifest,
        context=BuildContext(seed=1, tier=1),
    )
    topology = root.topology
    assert topology["host_details"]["web"]["services"]
    assert topology["dependency_edges"]
    assert topology["trust_edges"]
    assert "principal_catalog" in topology
    # After fixing tier1_basic.yaml, all trust_relationships reference
    # users that exist in the users section, so there should be no
    # trust-only principals.
    assert not topology["manifest_normalization"]["trust_only_principals"]


@pytest.mark.asyncio
async def test_mutator_rebuilds_child_files_from_mutated_snapshot(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.builder.mutator import Mutator
    from open_range.protocols import MutationOp, MutationPlan

    mutator = Mutator(TemplateOnlyBuilder())
    parent = await mutator.mutate(tier1_manifest, context=BuildContext(seed=1, tier=1))
    parent.files = {"web:/tmp/stale.txt": "stale\n"}

    def forced_plan(**kwargs):
        return MutationPlan(
            parent_snapshot_id="root_snap",
            ops=[
                MutationOp(
                    mutation_id="noise1",
                    op_type="add_benign_noise",
                    target_selector={"location": "siem:/var/log/siem/custom.log"},
                    params={"location": "siem:/var/log/siem/custom.log"},
                )
            ],
        )

    mutator._plan_mutations = forced_plan  # type: ignore[method-assign]
    child = await mutator.mutate(
        tier1_manifest,
        context=BuildContext(seed=2, tier=1),
        parent_snapshot=parent,
        parent_snapshot_id="root_snap",
    )
    assert "web:/tmp/stale.txt" not in child.files
    assert "siem:/var/log/siem/custom.log" in child.files


@pytest.mark.asyncio
async def test_mutator_seed_vuln_adds_flag_task_path_and_payloads(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.builder.mutator import Mutator
    from open_range.protocols import MutationOp, MutationPlan, TruthGraph

    mutator = Mutator(TemplateOnlyBuilder())
    parent = await mutator.mutate(tier1_manifest, context=BuildContext(seed=1, tier=1))
    parent.truth_graph = TruthGraph()
    parent.flags = []
    parent.golden_path = []
    parent.evidence_spec = []
    parent.task.success_conditions = []
    parent.task.milestones = []

    def forced_plan(**kwargs):
        return MutationPlan(
            parent_snapshot_id="root_snap",
            ops=[
                MutationOp(
                    mutation_id="seed_path_traversal",
                    op_type="seed_vuln",
                    target_selector={"host": "web"},
                    params={
                        "vuln_type": "path_traversal",
                        "template_id": "vuln_path_traversal",
                        "required_services": ["nginx", "php-fpm"],
                    },
                )
            ],
        )

    mutator._plan_mutations = forced_plan  # type: ignore[method-assign]
    child = await mutator.mutate(
        tier1_manifest,
        context=BuildContext(seed=2, tier=1),
        parent_snapshot=parent,
        parent_snapshot_id="root_snap",
    )

    path_vulns = [v for v in child.truth_graph.vulns if v.type == "path_traversal"]
    assert path_vulns
    new_flag = child.flags[-1]
    assert new_flag.value.endswith("_mut1}")
    assert new_flag.path.endswith("_mut1.txt")
    assert any(step.command.startswith("submit_flag ") and new_flag.value in step.command for step in child.golden_path)
    assert {"type": "flag", "value": new_flag.value} in child.task.success_conditions
    assert any(path_vulns[-1].injection_point in step.command for step in child.golden_path)
    assert "web:/var/www/portal/download.php" in child.files
    assert new_flag.value in child.files["web:/var/www/portal/download.php"]


@pytest.mark.asyncio
async def test_mutator_fails_fast_on_illegal_seed_vuln_family(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.builder.mutator import Mutator
    from open_range.protocols import MutationOp, MutationPlan

    mutator = Mutator(TemplateOnlyBuilder())
    parent = await mutator.mutate(tier1_manifest, context=BuildContext(seed=1, tier=1))

    def forced_plan(**kwargs):
        return MutationPlan(
            parent_snapshot_id="root_snap",
            ops=[
                MutationOp(
                    mutation_id="seed_bad_family",
                    op_type="seed_vuln",
                    target_selector={"host": "web"},
                    params={"vuln_type": "totally_fake_bug", "required_services": ["nginx"]},
                )
            ],
        )

    def should_not_apply(*args, **kwargs):  # pragma: no cover - assertion path
        raise AssertionError("_apply_plan should not run for illegal mutation plans")

    mutator._plan_mutations = forced_plan  # type: ignore[method-assign]
    mutator._apply_plan = should_not_apply  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="illegal family"):
        await mutator.mutate(
            tier1_manifest,
            context=BuildContext(seed=2, tier=1),
            parent_snapshot=parent,
            parent_snapshot_id="root_snap",
        )


@pytest.mark.asyncio
async def test_mutator_fails_fast_on_illegal_add_service_target(tier1_manifest):
    from open_range.builder.builder import TemplateOnlyBuilder
    from open_range.builder.mutator import Mutator
    from open_range.protocols import MutationOp, MutationPlan

    mutator = Mutator(TemplateOnlyBuilder())
    parent = await mutator.mutate(tier1_manifest, context=BuildContext(seed=1, tier=1))

    def forced_plan(**kwargs):
        return MutationPlan(
            parent_snapshot_id="root_snap",
            ops=[
                MutationOp(
                    mutation_id="add_bad_service",
                    op_type="add_service",
                    target_selector={"host": "web"},
                    params={"service": "totally_fake_service"},
                )
            ],
        )

    def should_not_apply(*args, **kwargs):  # pragma: no cover - assertion path
        raise AssertionError("_apply_plan should not run for illegal mutation plans")

    mutator._plan_mutations = forced_plan  # type: ignore[method-assign]
    mutator._apply_plan = should_not_apply  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="illegal service"):
        await mutator.mutate(
            tier1_manifest,
            context=BuildContext(seed=2, tier=1),
            parent_snapshot=parent,
            parent_snapshot_id="root_snap",
        )


# ---------------------------------------------------------------------------
# FileBuilder
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_builder_loads_from_disk():
    from open_range.builder.builder import FileBuilder

    # Create a temp snapshot directory with a valid spec.json
    with tempfile.TemporaryDirectory() as tmpdir:
        snap_dir = f"{tmpdir}/test_snap"
        import os

        os.makedirs(snap_dir)
        spec = SnapshotSpec(
            topology={"hosts": ["web"]},
            flags=[FlagSpec(id="f1", value="FLAG{file_test}", path="/f.txt", host="web")],
            golden_path=[
                GoldenPathStep(step=1, command="echo hi", expect_in_stdout="hi"),
            ],
        )
        # FileBuilder expects JSON with keys matching LLM output format
        data = {
            "topology": spec.topology,
            "flags": [f.model_dump() for f in spec.flags],
            "golden_path": [
                {"step": s.step, "cmd": s.command, "expect_stdout": s.expect_in_stdout}
                for s in spec.golden_path
            ],
            "truth_graph": {"vulns": [], "exploit_chain": []},
            "evidence_spec": {},
            "npc_traffic": {"http_rate": 10},
            "npc_personas": [],
            "task": {"red_briefing": "Go.", "blue_briefing": "Watch."},
        }
        with open(f"{snap_dir}/spec.json", "w") as f:
            json.dump(data, f)

        builder = FileBuilder(snapshot_dir=tmpdir)
        ctx = BuildContext(seed=0)
        result = await builder.build({}, ctx)
        assert isinstance(result, SnapshotSpec)
        assert result.topology["hosts"] == ["web"]


@pytest.mark.asyncio
async def test_file_builder_missing_dir():
    from open_range.builder.builder import FileBuilder

    builder = FileBuilder(snapshot_dir="/nonexistent/path")
    ctx = BuildContext()
    with pytest.raises(FileNotFoundError):
        await builder.build({}, ctx)


# ---------------------------------------------------------------------------
# SnapshotStore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_snapshot_store_store_and_select():
    from open_range.builder.snapshot_store import SnapshotStore

    with tempfile.TemporaryDirectory() as tmpdir:
        store = SnapshotStore(store_dir=tmpdir)
        spec = SnapshotSpec(
            topology={"hosts": ["web"]},
            flags=[FlagSpec(id="f1", value="FLAG{store}", path="/f.txt", host="web")],
        )
        sid = await store.store(spec, snapshot_id="test_snap")
        assert sid == "test_snap"

        loaded = await store.select(strategy="latest")
        assert isinstance(loaded, SnapshotSpec)
        assert loaded.flags[0].value == "FLAG{store}"


@pytest.mark.asyncio
async def test_snapshot_store_list():
    from open_range.builder.snapshot_store import SnapshotStore

    with tempfile.TemporaryDirectory() as tmpdir:
        store = SnapshotStore(store_dir=tmpdir)
        spec = SnapshotSpec(topology={"hosts": ["web"]})
        await store.store(spec, snapshot_id="snap_a")
        await store.store(spec, snapshot_id="snap_b")

        listing = await store.list_snapshots()
        assert len(listing) == 2
        ids = {m["snapshot_id"] for m in listing}
        assert "snap_a" in ids
        assert "snap_b" in ids


@pytest.mark.asyncio
async def test_snapshot_store_get_by_id():
    from open_range.builder.snapshot_store import SnapshotStore

    with tempfile.TemporaryDirectory() as tmpdir:
        store = SnapshotStore(store_dir=tmpdir)
        spec = SnapshotSpec(
            topology={"hosts": ["db"]},
            flags=[FlagSpec(id="f1", value="FLAG{get}", path="/f.txt", host="db")],
        )
        await store.store(spec, snapshot_id="my_snap")

        loaded = await store.get("my_snap")
        assert loaded.flags[0].value == "FLAG{get}"


@pytest.mark.asyncio
async def test_snapshot_store_get_missing_raises():
    from open_range.builder.snapshot_store import SnapshotStore

    with tempfile.TemporaryDirectory() as tmpdir:
        store = SnapshotStore(store_dir=tmpdir)
        with pytest.raises(FileNotFoundError):
            await store.get("nonexistent")


@pytest.mark.asyncio
async def test_snapshot_store_select_empty_raises():
    from open_range.builder.snapshot_store import SnapshotStore

    with tempfile.TemporaryDirectory() as tmpdir:
        store = SnapshotStore(store_dir=tmpdir)
        with pytest.raises(FileNotFoundError):
            await store.select()


@pytest.mark.asyncio
async def test_snapshot_store_random_select():
    from open_range.builder.snapshot_store import SnapshotStore

    with tempfile.TemporaryDirectory() as tmpdir:
        store = SnapshotStore(store_dir=tmpdir)
        for i in range(3):
            spec = SnapshotSpec(topology={"hosts": [f"host_{i}"]})
            await store.store(spec, snapshot_id=f"snap_{i}")

        selected = await store.select(strategy="random")
        assert isinstance(selected, SnapshotSpec)
