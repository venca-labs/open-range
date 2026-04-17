from __future__ import annotations

from types import SimpleNamespace

from open_range.catalog.contracts import STANDARD_ATTACK_OBJECTIVE_NAMES
from open_range.catalog.objectives import (
    objective_rule_for_predicate_name,
    public_objective_predicate_names,
    weakness_objective_tags_for_kind,
)
from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.objectives import (
    PUBLIC_OBJECTIVE_PREDICATE_NAMES,
    evaluate_objective_grader_live,
    objective_event_for_predicate,
    objective_grader_for_predicate,
    objective_tags_for_predicate,
    resolve_objective,
)
from open_range.objectives.engine import PredicateEngine
from open_range.weaknesses import CatalogWeaknessSeeder
from tests.support import manifest_payload


def _manifest_payload() -> dict:
    payload = manifest_payload()
    payload["objectives"]["red"] = [
        {"predicate": "asset_read(finance_docs)"},
        {"predicate": "credential_obtained(idp_admin_cred)"},
    ]
    return payload


def test_predicate_engine_builds_service_native_graders_for_red_objectives() -> None:
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    predicates = PredicateEngine(world)

    graders = {
        objective.predicate: predicates.objective_grader(objective.predicate)
        for objective in world.red_objectives
    }

    assert graders["asset_read(finance_docs)"] is not None
    assert graders["asset_read(finance_docs)"].grader_kind == "file_exists"
    assert graders["credential_obtained(idp_admin_cred)"] is not None
    assert graders["credential_obtained(idp_admin_cred)"].grader_kind == "event_present"
    assert (
        graders["credential_obtained(idp_admin_cred)"].objective_tag
        == "privilege_escalation"
    )


def test_objective_rule_registry_keeps_special_case_predicates_stable() -> None:
    assert objective_tags_for_predicate(
        "asset_read(finance_docs)",
        asset_location="svc-db:/var/lib/mysql/finance_docs.sql",
        owner_service="svc-db",
        target_id="finance_docs",
    ) == ("db_access",)
    assert objective_tags_for_predicate(
        "asset_read(finance_docs)",
        asset_location="svc-fileshare:/srv/shared/finance_docs.txt",
        owner_service="svc-fileshare",
        target_id="finance_docs",
    ) == ("file_access",)

    grader = objective_grader_for_predicate(
        "credential_obtained(idp_admin_cred)",
        target_id="idp_admin_cred",
    )

    assert grader is not None
    assert grader.objective_tag == "privilege_escalation"
    assert grader.event_type == "CredentialObtained"
    assert grader.grader_kind == "event_present"


def test_catalog_public_objective_names_drive_public_allowlist() -> None:
    assert public_objective_predicate_names() == PUBLIC_OBJECTIVE_PREDICATE_NAMES


def test_catalog_has_rule_data_for_direct_and_special_objectives() -> None:
    for objective_tag in STANDARD_ATTACK_OBJECTIVE_NAMES:
        rule = objective_rule_for_predicate_name(objective_tag)
        assert rule is not None
        assert rule.resolution_kind == "direct_objective"
        assert rule.objective_tag == objective_tag

    assert objective_rule_for_predicate_name("asset_read") is not None
    assert (
        objective_rule_for_predicate_name("asset_read").resolution_kind == "asset_read"
    )
    assert objective_rule_for_predicate_name("credential_obtained") is not None
    assert (
        objective_rule_for_predicate_name("credential_obtained").resolution_kind
        == "credential_obtained"
    )
    assert objective_rule_for_predicate_name("outbound_service").event_type == (
        "PersistenceEstablished"
    )
    assert objective_rule_for_predicate_name("intrusion_detected").default_service == (
        "svc-siem"
    )


def test_catalog_objective_resolution_keeps_event_and_target_contracts() -> None:
    outbound = resolve_objective(
        "outbound_service(svc-web)",
        target_id="svc-web",
        service_ids=frozenset({"svc-web", "svc-idp"}),
    )
    assert outbound.target_service == "svc-web"
    assert outbound.event_type == "PersistenceEstablished"

    credential = resolve_objective(
        "credential_obtained(idp_admin_cred)",
        target_id="idp_admin_cred",
    )
    assert credential.target_kind == "asset"
    assert credential.target_service == "svc-idp"
    assert credential.event_type == "CredentialObtained"
    assert objective_event_for_predicate(
        "privilege_escalation(svc-idp)",
        target_id="svc-idp",
        default_service="svc-idp",
    ) == ("PrivilegeEscalation", "svc-idp")


def test_catalog_weakness_objective_tags_cover_current_examples() -> None:
    assert weakness_objective_tags_for_kind("code_web", "sql_injection") == (
        "db_access",
    )
    assert weakness_objective_tags_for_kind(
        "config_identity",
        "overbroad_service_account",
    ) == ("privilege_escalation",)
    assert weakness_objective_tags_for_kind(
        "workflow_abuse",
        "document_share_abuse",
    ) == ("file_access",)


def test_live_event_backed_admin_grader_still_requires_the_event() -> None:
    payload = manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "config_identity",
            "kind": "admin_surface_exposed",
            "target": "service:svc-idp",
        }
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    predicates = PredicateEngine(world)
    grader = predicates.objective_grader("unauthorized_admin_login(svc-idp)")
    assert grader is not None

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del service, cmd, timeout
            return SimpleNamespace(
                ok=True,
                stdout="target_ref=svc-idp\nadmin_surface_public=true\n",
                stderr="",
            )

    snapshot = SimpleNamespace(world=world, file_assets={}, db_seed_state={})

    assert (
        evaluate_objective_grader_live(
            "unauthorized_admin_login(svc-idp)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(),
            service_health={"svc-idp": 1.0},
            outputs=("admin_surface public",),
        )
        is False
    )

    assert (
        evaluate_objective_grader_live(
            "unauthorized_admin_login(svc-idp)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(
                SimpleNamespace(
                    event_type="UnauthorizedCredentialUse",
                    target_entity="svc-idp",
                    linked_objective_predicates=("unauthorized_admin_login(svc-idp)",),
                ),
            ),
            service_health={"svc-idp": 1.0},
            outputs=("admin_surface public",),
        )
        is True
    )


def test_live_admin_grader_requires_probe_when_realized_effect_exists() -> None:
    payload = manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "config_identity",
            "kind": "admin_surface_exposed",
            "target": "service:svc-idp",
        }
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    predicates = PredicateEngine(world)
    grader = predicates.objective_grader("unauthorized_admin_login(svc-idp)")
    assert grader is not None

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del service, cmd, timeout
            return SimpleNamespace(ok=False, stdout="", stderr="miss")

    snapshot = SimpleNamespace(world=world, file_assets={}, db_seed_state={})
    assert (
        evaluate_objective_grader_live(
            "unauthorized_admin_login(svc-idp)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(
                SimpleNamespace(
                    event_type="UnauthorizedCredentialUse",
                    target_entity="svc-idp",
                    linked_objective_predicates=("unauthorized_admin_login(svc-idp)",),
                ),
            ),
            service_health={"svc-idp": 1.0},
            outputs=("admin_surface_public=true",),
        )
        is False
    )


def test_live_privilege_grader_probes_realized_config_without_output_tokens() -> None:
    payload = manifest_payload()
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "config_identity",
            "kind": "overbroad_service_account",
            "target": "service:svc-idp",
        }
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    predicates = PredicateEngine(world)
    grader = predicates.objective_grader("privilege_escalation(svc-idp)")
    assert grader is not None

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del timeout
            if (
                service == "svc-idp"
                and "service_account_scope" in cmd
                and "svc-db" in cmd
                and "svc-idp" in cmd
            ):
                return SimpleNamespace(ok=True, stdout="", stderr="")
            return SimpleNamespace(ok=False, stdout="", stderr="miss")

    snapshot = SimpleNamespace(world=world, file_assets={}, db_seed_state={})

    assert (
        evaluate_objective_grader_live(
            "privilege_escalation(svc-idp)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(
                SimpleNamespace(
                    event_type="PrivilegeEscalation",
                    target_entity="svc-idp",
                    linked_objective_predicates=("privilege_escalation(svc-idp)",),
                ),
            ),
            service_health={"svc-idp": 1.0},
            outputs=("",),
        )
        is True
    )


def test_live_outbound_grader_probes_ssrf_realizations_without_output_tokens() -> None:
    payload = manifest_payload()
    payload["objectives"]["red"] = [{"predicate": "outbound_service(svc-web)"}]
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "code_web",
            "kind": "ssrf",
            "target": "service:svc-web",
        }
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    predicates = PredicateEngine(world)
    grader = predicates.objective_grader("outbound_service(svc-web)")
    assert grader is not None

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del timeout
            if (
                service == "svc-siem"
                and "egress-canary" in cmd
                and world.weaknesses[0].id in cmd
            ):
                return SimpleNamespace(ok=True, stdout="", stderr="")
            return SimpleNamespace(ok=False, stdout="", stderr="miss")

    snapshot = SimpleNamespace(world=world, file_assets={}, db_seed_state={})

    assert (
        evaluate_objective_grader_live(
            "outbound_service(svc-web)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(
                SimpleNamespace(
                    event_type="PersistenceEstablished",
                    target_entity="svc-web",
                    linked_objective_predicates=("outbound_service(svc-web)",),
                ),
            ),
            service_health={"svc-web": 1.0},
            outputs=("",),
        )
        is True
    )


def test_live_db_read_grader_uses_mtls_mysql_flags() -> None:
    grader = SimpleNamespace(
        grader_kind="db_row_read",
        service_id="svc-db",
        target_id="finance_docs",
        expected_ref="seeded-finance_docs",
    )
    calls: list[tuple[str, str]] = []

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del timeout
            calls.append((service, cmd))
            return SimpleNamespace(
                ok=True,
                stdout="seeded-finance_docs\n",
                stderr="",
            )

    snapshot = SimpleNamespace(
        world=SimpleNamespace(security_runtime=SimpleNamespace(mtls={"enabled": True})),
        file_assets={},
        db_seed_state={},
    )

    assert (
        evaluate_objective_grader_live(
            "asset_read(finance_docs)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(),
            service_health={"svc-db": 1.0},
            outputs=(),
        )
        is True
    )
    assert calls == [("svc-db", calls[0][1])]
    assert "--protocol=TCP" in calls[0][1]
    assert "--ssl-ca=/etc/mtls/ca.pem" in calls[0][1]
    assert "--ssl-cert=/etc/mtls/cert.pem" in calls[0][1]
    assert "--ssl-key=/etc/mtls/key.pem" in calls[0][1]


def test_live_db_read_grader_falls_back_without_mtls() -> None:
    grader = SimpleNamespace(
        grader_kind="db_row_read",
        service_id="svc-db",
        target_id="finance_docs",
        expected_ref="seeded-finance_docs",
    )
    calls: list[tuple[str, str]] = []

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del timeout
            calls.append((service, cmd))
            return SimpleNamespace(
                ok=True,
                stdout="seeded-finance_docs\n",
                stderr="",
            )

    snapshot = SimpleNamespace(
        world=SimpleNamespace(security_runtime=SimpleNamespace(mtls={})),
        file_assets={},
        db_seed_state={},
    )

    assert (
        evaluate_objective_grader_live(
            "asset_read(finance_docs)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(),
            service_health={"svc-db": 1.0},
            outputs=(),
        )
        is True
    )
    assert calls == [("svc-db", calls[0][1])]
    assert "--ssl-ca=/etc/mtls/ca.pem" not in calls[0][1]
    assert "--ssl-cert=/etc/mtls/cert.pem" not in calls[0][1]
    assert "--ssl-key=/etc/mtls/key.pem" not in calls[0][1]


def test_live_outbound_grader_requires_probe_when_ssrf_realization_exists() -> None:
    payload = manifest_payload()
    payload["objectives"]["red"] = [{"predicate": "outbound_service(svc-web)"}]
    payload["security"]["pinned_weaknesses"] = [
        {
            "family": "code_web",
            "kind": "ssrf",
            "target": "service:svc-web",
        }
    ]
    world = CatalogWeaknessSeeder().apply(
        EnterpriseSaaSManifestCompiler().compile(payload)
    )
    predicates = PredicateEngine(world)
    grader = predicates.objective_grader("outbound_service(svc-web)")
    assert grader is not None

    class _Pods:
        async def exec(self, service: str, cmd: str, timeout: float = 10.0):
            del service, cmd, timeout
            return SimpleNamespace(ok=False, stdout="", stderr="miss")

    snapshot = SimpleNamespace(world=world, file_assets={}, db_seed_state={})
    assert (
        evaluate_objective_grader_live(
            "outbound_service(svc-web)",
            grader,
            snapshot=snapshot,
            pods=_Pods(),
            events=(
                SimpleNamespace(
                    event_type="PersistenceEstablished",
                    target_entity="svc-web",
                    linked_objective_predicates=("outbound_service(svc-web)",),
                ),
            ),
            service_health={"svc-web": 1.0},
            outputs=("http://127.0.0.1/internal",),
        )
        is False
    )
