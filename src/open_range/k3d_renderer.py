"""Render WorldIR into a Helm chart targeting k3d (multi-node k3s).

Extends ``EnterpriseSaaSKindRenderer`` but produces a k3d cluster config
instead of a Kind cluster config.  Zone isolation remains namespace-per-zone
with NetworkPolicies; the k3d backend adds multi-node support (1 server +
N agents) and proper subnet isolation (``172.29.0.0/16``).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from open_range.render import EnterpriseSaaSKindRenderer
from open_range.runtime_extensions import RenderExtensions
from open_range.snapshot import KindArtifacts
from open_range.synth import SynthArtifacts
from open_range.world_ir import ServiceSpec, WorldIR

logger = logging.getLogger(__name__)

# k3d cluster defaults
_K3D_SUBNET = "172.29.0.0/16"
_K3D_AGENTS = 2
_K3D_API_HOST = "127.0.0.1"
_K3D_API_PORT = "6550"
_K3D_K3S_IMAGE = "rancher/k3s:v1.31.6-k3s1"
_K3D_WAIT_TIMEOUT = "300s"
_DMZ_NODEPORT_BASE = 30080


class K3dRenderer(EnterpriseSaaSKindRenderer):
    """Render a WorldIR into a Helm chart and k3d cluster config.

    Subclasses ``EnterpriseSaaSKindRenderer`` to reuse all values
    generation logic.  Only the cluster config output differs: a k3d
    Simple config is written instead of a Kind Cluster config.
    """

    def __init__(
        self,
        chart_dir: Path | None = None,
        *,
        agents: int = _K3D_AGENTS,
        subnet: str = _K3D_SUBNET,
        api_host: str = _K3D_API_HOST,
        api_port: str = _K3D_API_PORT,
        k3s_image: str = _K3D_K3S_IMAGE,
        wait_timeout: str = _K3D_WAIT_TIMEOUT,
    ) -> None:
        super().__init__(chart_dir=chart_dir)
        self.agents = agents
        self.subnet = subnet
        self.api_host = api_host
        self.api_port = api_port
        self.k3s_image = k3s_image
        self.wait_timeout = wait_timeout

    def render(
        self,
        world: WorldIR,
        synth: SynthArtifacts,
        outdir: Path,
        *,
        extensions: RenderExtensions | None = None,
    ) -> KindArtifacts:
        """Render the Helm chart and k3d config to *outdir*.

        Delegates most work to ``EnterpriseSaaSKindRenderer.render()``
        then replaces the Kind config with a k3d config.
        """
        artifacts = super().render(world, synth, outdir, extensions=extensions)

        # Replace kind-config.yaml with k3d-config.yaml
        kind_config_path = Path(artifacts.kind_config_path)
        if kind_config_path.exists():
            kind_config_path.unlink()

        k3d_config = self._build_k3d_config(world)
        k3d_config_path = Path(outdir) / "k3d-config.yaml"
        k3d_config_path.write_text(
            yaml.dump(k3d_config, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )

        logger.info(
            "K3dRenderer: wrote k3d-config.yaml (%d agents, subnet %s)",
            self.agents,
            self.subnet,
        )

        # Return updated artifacts with the k3d config path
        return KindArtifacts(
            render_dir=artifacts.render_dir,
            chart_dir=artifacts.chart_dir,
            values_path=artifacts.values_path,
            kind_config_path=str(k3d_config_path),
            manifest_summary_path=artifacts.manifest_summary_path,
            rendered_files=(*artifacts.rendered_files, str(k3d_config_path)),
            chart_values=artifacts.chart_values,
            pinned_image_digests=artifacts.pinned_image_digests,
        )

    # ------------------------------------------------------------------
    # k3d cluster config
    # ------------------------------------------------------------------

    def _build_k3d_config(self, world: WorldIR) -> dict[str, Any]:
        """Generate a k3d Simple cluster config with DMZ port mappings.

        Disables Traefik and the default CNI (flannel) so the cluster
        is ready for a Cilium install managed separately.
        """
        # Extract DMZ services for port mapping
        host_by_id = {h.id: h for h in world.hosts}
        dmz_services: list[ServiceSpec] = []
        for svc in world.services:
            host = host_by_id.get(svc.host)
            if host and host.exposure == "public":
                dmz_services.append(svc)

        # Build port mappings for the k3d config
        ports: list[dict[str, Any]] = [
            {"port": "8080:80", "nodeFilters": ["loadbalancer"]},
            {"port": "8443:443", "nodeFilters": ["loadbalancer"]},
        ]

        if dmz_services:
            base = _DMZ_NODEPORT_BASE
            for i, svc in enumerate(dmz_services):
                np = base + i
                ports.append(
                    {
                        "port": f"{np}:{np}",
                        "nodeFilters": ["server:0"],
                    }
                )
        else:
            ports.append(
                {
                    "port": f"{_DMZ_NODEPORT_BASE}-{_DMZ_NODEPORT_BASE + 9}"
                    f":{_DMZ_NODEPORT_BASE}-{_DMZ_NODEPORT_BASE + 9}",
                    "nodeFilters": ["server:0"],
                }
            )

        extra_args: list[dict[str, Any]] = [
            {"arg": "--disable=traefik", "nodeFilters": ["server:*"]},
            {"arg": "--flannel-backend=none", "nodeFilters": ["server:*"]},
            {"arg": "--disable-network-policy", "nodeFilters": ["server:*"]},
        ]

        node_labels: list[dict[str, Any]] = [
            {"label": "openrange.io/role=agent", "nodeFilters": ["agent:*"]},
            {"label": "openrange.io/role=server", "nodeFilters": ["server:*"]},
        ]

        return {
            "apiVersion": "k3d.io/v1alpha5",
            "kind": "Simple",
            "metadata": {"name": "openrange"},
            "servers": 1,
            "agents": self.agents,
            "image": self.k3s_image,
            "subnet": self.subnet,
            "kubeAPI": {
                "host": self.api_host,
                "hostIP": self.api_host,
                "hostPort": self.api_port,
            },
            "ports": ports,
            "options": {
                "k3d": {
                    "wait": True,
                    "timeout": self.wait_timeout,
                },
                "k3s": {
                    "extraArgs": extra_args,
                    "nodeLabels": node_labels,
                },
            },
        }
