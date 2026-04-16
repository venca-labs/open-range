"""Kind renderer for `WorldIR`."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Protocol

import yaml

from open_range.image_policy import (
    SANDBOX_IMAGE_BY_ROLE,
    service_image_for_kind,
)
from open_range.runtime_extensions import (
    RenderExtensions,
    apply_service_runtime_extensions,
    merge_render_extensions,
)
from open_range.security_runtime import materialize_security_runtime
from open_range.snapshot import KindArtifacts
from open_range.synth import SynthArtifacts
from open_range.world_ir import GreenPersona, ServiceSpec, WorldIR

_CHART_DIR = Path(__file__).resolve().parent / "chart"


class KindRenderer(Protocol):
    def render(
        self,
        world: WorldIR,
        synth: SynthArtifacts,
        outdir: Path,
        *,
        extensions: RenderExtensions | None = None,
    ) -> KindArtifacts: ...


class EnterpriseSaaSKindRenderer:
    """Render `WorldIR` to a deterministic Kind/Helm artifact bundle."""

    def __init__(self, chart_dir: Path | None = None) -> None:
        self.chart_dir = chart_dir or _CHART_DIR

    def render(
        self,
        world: WorldIR,
        synth: SynthArtifacts,
        outdir: Path,
        *,
        extensions: RenderExtensions | None = None,
    ) -> KindArtifacts:
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        chart_out = outdir / "openrange"
        if chart_out.exists():
            shutil.rmtree(chart_out)
        shutil.copytree(self.chart_dir, chart_out)

        combined_extensions = merge_render_extensions(
            materialize_security_runtime(world, outdir),
            extensions,
        )
        values = self._build_values(world, synth, extensions=combined_extensions)
        kind_config = self._build_kind_config(world)
        summary = self._build_summary(
            world,
            values,
            summary_updates=(
                combined_extensions.summary_updates if combined_extensions else None
            ),
        )

        values_path = chart_out / "values.yaml"
        values_path.write_text(
            yaml.safe_dump(values, sort_keys=False), encoding="utf-8"
        )
        kind_config_path = outdir / "kind-config.yaml"
        kind_config_path.write_text(
            yaml.safe_dump(kind_config, sort_keys=False), encoding="utf-8"
        )
        summary_path = outdir / "manifest-summary.json"
        summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        pinned = {
            service.id: self._image_digest_for(service.kind)
            for service in world.services
        }
        return KindArtifacts(
            render_dir=str(outdir),
            chart_dir=str(chart_out),
            values_path=str(values_path),
            kind_config_path=str(kind_config_path),
            manifest_summary_path=str(summary_path),
            rendered_files=tuple(
                [
                    str(values_path),
                    str(kind_config_path),
                    str(summary_path),
                    *synth.generated_files,
                    *(
                        combined_extensions.rendered_files
                        if combined_extensions
                        else ()
                    ),
                ]
            ),
            chart_values=values,
            pinned_image_digests=pinned,
        )

    @staticmethod
    def _build_values(
        world: WorldIR,
        synth: SynthArtifacts,
        *,
        extensions: RenderExtensions | None = None,
    ) -> dict[str, Any]:
        host_by_id = {host.id: host for host in world.hosts}
        service_by_id = {service.id: service for service in world.services}
        zones: dict[str, dict[str, Any]] = {}
        for zone in world.zones:
            zones[zone] = {
                "hosts": [host.id for host in world.hosts if host.zone == zone],
            }

        services: dict[str, dict[str, Any]] = {}
        for service in world.services:
            host = host_by_id[service.host]
            services[service.id] = {
                "enabled": True,
                "host": service.host,
                "zone": host.zone,
                "kind": service.kind,
                "image": service_image_for_kind(service.kind),
                "ports": [{"name": f"p{port}", "port": port} for port in service.ports],
                "dependencies": list(service.dependencies),
                "telemetry_surfaces": list(service.telemetry_surfaces),
                "env": _service_env(service),
                "command": _service_command(service),
                "payloads": [
                    {
                        "key": synth_file.key,
                        "mountPath": synth_file.mount_path,
                        "content": synth_file.content,
                    }
                    for synth_file in synth.service_payloads.get(service.id, ())
                ],
            }

        sandboxes = {
            "sandbox-red": {
                "enabled": True,
                "zone": "external" if "external" in world.zones else world.zones[0],
                "image": SANDBOX_IMAGE_BY_ROLE["red"],
                "role": "red",
                "command": ["/bin/sh", "-lc", "sleep infinity"],
            },
            "sandbox-blue": {
                "enabled": True,
                "zone": "management"
                if "management" in world.zones
                else world.zones[-1],
                "image": SANDBOX_IMAGE_BY_ROLE["blue"],
                "role": "blue",
                "command": ["/bin/sh", "-lc", "sleep infinity"],
            },
        }
        for persona in world.green_personas:
            sandboxes[_sandbox_name(persona)] = _green_sandbox(persona, host_by_id)

        users = [
            {
                "username": user.id,
                "password": _default_password(user.id),
                "email": user.email,
            }
            for user in world.users
        ]

        values = {
            "global": {
                "namePrefix": _name_prefix(world.world_id),
                "snapshotId": world.world_id,
            },
            "world": {
                "id": world.world_id,
                "family": world.world_family,
                "seed": world.seed,
                "targetRedPathDepth": world.target_red_path_depth,
                "targetBlueSignalPoints": world.target_blue_signal_points,
            },
            "zones": zones,
            "services": services,
            "sandboxes": sandboxes,
            "users": users,
            "mailboxes": {
                mailbox: list(messages) for mailbox, messages in synth.mailboxes.items()
            },
            "firewallRules": _firewall_rules(world, host_by_id, service_by_id),
            "assets": [asset.model_dump(mode="json") for asset in world.assets],
            "weaknesses": [
                weakness.model_dump(mode="json") for weakness in world.weaknesses
            ],
            "telemetryEdges": [
                edge.model_dump(mode="json") for edge in world.telemetry_edges
            ],
        }
        if extensions is not None:
            values["services"] = apply_service_runtime_extensions(
                values["services"],
                extensions.services,
            )
            values.update(extensions.values)
        return values

    @staticmethod
    def _build_kind_config(world: WorldIR) -> dict[str, Any]:
        return {
            "kind": "Cluster",
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "name": "openrange",
            "nodes": [
                {
                    "role": "control-plane",
                    "labels": {
                        "openrange.world_id": world.world_id,
                        "openrange.world_family": world.world_family,
                    },
                }
            ],
        }

    @staticmethod
    def _build_summary(
        world: WorldIR,
        values: dict[str, Any],
        *,
        summary_updates: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        summary = {
            "world_id": world.world_id,
            "service_count": len(world.services),
            "zone_count": len(world.zones),
            "sandbox_count": len(values.get("sandboxes", {})),
            "asset_count": len(world.assets),
            "weakness_count": len(world.weaknesses),
            "values_hash": hashlib.sha256(
                json.dumps(values, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest(),
        }
        if summary_updates:
            summary.update(summary_updates)
        return summary

    @staticmethod
    def _image_digest_for(kind: str) -> str:
        image = service_image_for_kind(kind)
        digest = hashlib.sha256(image.encode("utf-8")).hexdigest()[:24]
        return f"{image}@sha256:{digest}"


def _service_env(service: ServiceSpec) -> dict[str, str]:
    if service.kind == "db":
        return {
            "MYSQL_ROOT_PASSWORD": "rootpass",
            "MYSQL_DATABASE": "app",
            "MYSQL_USER": "app",
            "MYSQL_PASSWORD": "app-pass",
        }
    if service.kind == "idp":
        return {
            "LDAP_ORGANISATION": "OpenRange",
            "LDAP_DOMAIN": "corp.local",
            "LDAP_ADMIN_PASSWORD": "adminpass",
        }
    if service.kind == "email":
        return {
            "MAILNAME": "corp.local",
        }
    if service.kind == "fileshare":
        return {
            "USER": "analyst;analyst-pass",
            "SHARE": "shared;/srv/shared;yes;no;yes;analyst",
        }
    return {}


def _service_command(service: ServiceSpec) -> list[str]:
    if service.kind == "idp":
        # The osixia/openldap image expects mounted certs to be copied into a
        # writable service directory before startup mutates ownership.
        return ["/container/tool/run", "--copy-service"]
    if service.kind == "siem":
        return [
            "/bin/sh",
            "-lc",
            (
                "mkdir -p /srv/http/siem && touch /srv/http/siem/all.log /srv/http/siem/egress-canary.log && "
                "("
                "while true; do "
                "{ "
                "IFS= read -r request_line || exit 0; "
                "printf '%s\\n' \"$request_line\" >> /srv/http/siem/egress-canary.log; "
                "path=$(printf '%s' \"$request_line\" | awk '{print $2}'); "
                "slug=${path##*/}; slug=${slug%%\\?*}; "
                'body="OPENRANGE-EFFECT:egress:${slug}"; '
                'printf \'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: %s\\r\\n\\r\\n%s\' "${#body}" "$body"; '
                "} | busybox nc -lp 9201 -q 1; "
                "done"
                ") & "
                "busybox httpd -f -p 9200 -h /srv/http/siem"
            ),
        ]
    return []


def _firewall_rules(
    world: WorldIR,
    host_by_id: dict[str, Any],
    service_by_id: dict[str, ServiceSpec],
) -> list[dict[str, Any]]:
    rules: dict[tuple[str, str], set[int]] = {}

    def allow(from_zone: str, to_zone: str, ports: tuple[int, ...]) -> None:
        if not ports:
            return
        rules.setdefault((from_zone, to_zone), set()).update(ports)

    public_services = [
        service
        for service in world.services
        if host_by_id[service.host].exposure == "public"
    ]
    for service in public_services:
        allow("external", host_by_id[service.host].zone, service.ports)

    for service in world.services:
        from_zone = host_by_id[service.host].zone
        for dep_id in service.dependencies:
            dep = service_by_id.get(dep_id)
            if dep is None:
                continue
            allow(from_zone, host_by_id[dep.host].zone, dep.ports)

    for edge in world.telemetry_edges:
        source = service_by_id.get(edge.source)
        target = service_by_id.get(edge.target)
        if source is None or target is None:
            continue
        allow(host_by_id[source.host].zone, host_by_id[target.host].zone, target.ports)

    role_zone_map = {
        role: host_by_id[user.primary_host].zone
        for role in {user.role for user in world.users}
        for user in world.users
        if user.role == role and user.primary_host in host_by_id
    }
    for workflow in world.workflows:
        for step in workflow.steps:
            if not step.service or step.actor_role not in role_zone_map:
                continue
            service = service_by_id.get(step.service)
            if service is None:
                continue
            allow(
                role_zone_map[step.actor_role],
                host_by_id[service.host].zone,
                service.ports,
            )

    return [
        {
            "fromZone": from_zone,
            "toZone": to_zone,
            "action": "allow",
            "ports": sorted(ports),
        }
        for (from_zone, to_zone), ports in sorted(rules.items())
    ]


def _green_sandbox(persona: GreenPersona, host_by_id: dict[str, Any]) -> dict[str, Any]:
    zone = (
        host_by_id[persona.home_host].zone
        if persona.home_host in host_by_id
        else "corp"
    )
    return {
        "enabled": True,
        "zone": zone,
        "image": SANDBOX_IMAGE_BY_ROLE["green"],
        "role": "green",
        "persona": persona.id,
        "mailbox": persona.mailbox,
        "homeHost": persona.home_host,
        "command": ["/bin/sh", "-lc", "sleep infinity"],
    }


def _sandbox_name(persona: GreenPersona) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in persona.id).strip("-")
    return f"sandbox-green-{safe}"


def _name_prefix(world_id: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in world_id).strip("-")
    return safe[:40] or "openrange"


def _default_password(user_id: str) -> str:
    return f"{user_id}-pass"
