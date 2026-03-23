"""Boot and tear down rendered snapshot Helm releases on a k3d cluster.

Extends ``KindBackend`` but uses k3d instead of Kind for cluster
management and image loading.  The k3d cluster provides multi-node
support (1 server + N agents) with proper subnet isolation.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from open_range.cluster import KindBackend

logger = logging.getLogger(__name__)

# Default cluster name matches deploy/k3d/k3d-up.sh
_DEFAULT_CLUSTER = "openrange"


def resolve_kubectl_cmd(k3d_cluster: str = _DEFAULT_CLUSTER) -> tuple[str, ...]:
    """Return a kubectl command prefix configured for the k3d context.

    k3d clusters expose a kubeconfig context named ``k3d-<cluster>``.
    We prefer a host kubectl when present; otherwise fall back to
    running kubectl inside the k3d server container.
    """
    if shutil.which("kubectl"):
        return ("kubectl", "--context", f"k3d-{k3d_cluster}")
    return (
        "docker",
        "exec",
        f"k3d-{k3d_cluster}-server-0",
        "kubectl",
    )


@dataclass
class K3dClusterInfo:
    """Metadata about a running k3d cluster."""

    name: str
    agents: int
    subnet: str
    api_host: str = "127.0.0.1"
    api_port: int = 6550
    context: str = ""

    def __post_init__(self) -> None:
        if not self.context:
            self.context = f"k3d-{self.name}"


class K3dBackend(KindBackend):
    """Boot and tear down rendered snapshot Helm charts on k3d.

    Extends ``KindBackend`` to use k3d for image loading and cluster
    lifecycle management.  The ``boot()`` / ``teardown()`` interface
    remains identical so call sites can swap backends transparently.
    """

    def __init__(
        self,
        *,
        kind_cluster: str = _DEFAULT_CLUSTER,
        k3d_agents: int = 2,
        k3d_subnet: str = "172.29.0.0/16",
    ) -> None:
        super().__init__(kind_cluster=kind_cluster)
        self.k3d_cluster = kind_cluster
        self.k3d_agents = k3d_agents
        self.k3d_subnet = k3d_subnet

    # ------------------------------------------------------------------
    # Cluster lifecycle
    # ------------------------------------------------------------------

    def create_cluster(
        self,
        *,
        config_path: Path | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> K3dClusterInfo:
        """Create a k3d cluster.

        If *config_path* points to a rendered k3d-config.yaml, it is
        used directly.  Otherwise a default k3d configuration is applied.

        Returns metadata about the created cluster.
        """
        if self.cluster_exists():
            logger.info(
                "k3d cluster '%s' already exists, skipping creation", self.k3d_cluster
            )
            return K3dClusterInfo(
                name=self.k3d_cluster,
                agents=self.k3d_agents,
                subnet=self.k3d_subnet,
            )

        cmd: list[str]
        if config_path and config_path.exists():
            cmd = ["k3d", "cluster", "create", "--config", str(config_path)]
        else:
            cmd = [
                "k3d",
                "cluster",
                "create",
                self.k3d_cluster,
                "--agents",
                str(self.k3d_agents),
                "--subnet",
                self.k3d_subnet,
                "--k3s-arg",
                "--disable=traefik@server:*",
                "--k3s-arg",
                "--flannel-backend=none@server:*",
                "--k3s-arg",
                "--disable-network-policy@server:*",
                "--port",
                "30080-30089:30080-30089@server:0",
                "--wait",
                "--timeout",
                "300s",
            ]

        import os

        run_env = dict(os.environ)
        if env_overrides:
            run_env.update(env_overrides)

        self._run(cmd, timeout=360.0)
        logger.info("Created k3d cluster '%s'", self.k3d_cluster)

        self._run(
            ["kubectl", "config", "use-context", f"k3d-{self.k3d_cluster}"],
            timeout=10.0,
        )

        return K3dClusterInfo(
            name=self.k3d_cluster,
            agents=self.k3d_agents,
            subnet=self.k3d_subnet,
        )

    def delete_cluster(self) -> None:
        """Delete the k3d cluster if it exists."""
        if not self.cluster_exists():
            logger.info(
                "k3d cluster '%s' does not exist, nothing to delete", self.k3d_cluster
            )
            return
        self._run(
            ["k3d", "cluster", "delete", self.k3d_cluster],
            timeout=120.0,
        )
        logger.info("Deleted k3d cluster '%s'", self.k3d_cluster)

    def cluster_exists(self) -> bool:
        """Check whether the k3d cluster is currently running."""
        result = subprocess.run(
            ["k3d", "cluster", "list", "-o", "json"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return False
        return f'"name":"{self.k3d_cluster}"' in result.stdout

    # ------------------------------------------------------------------
    # Image management -- override Kind's image loading
    # ------------------------------------------------------------------

    def prepare_images(self, chart_dir: Path) -> None:
        """Override KindBackend.prepare_images to use k3d image import."""
        for image in self._chart_images(chart_dir):
            self._ensure_image_loaded(image)

    def _ensure_image_loaded(self, image: str) -> None:
        """Pull (if needed) and import an image into the k3d cluster."""
        if not image:
            return
        if not self._docker_image_present(image):
            try:
                self._run(["docker", "pull", image], timeout=300.0)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to pre-pull image %s: %s", image, exc)
                return
        self._load_single_image(image)

    def _load_single_image(self, image: str) -> None:
        """Import a single image into the k3d cluster (best-effort)."""
        try:
            self._run(
                ["k3d", "image", "import", "-c", self.k3d_cluster, image],
                timeout=120.0,
            )
            logger.debug(
                "Imported image %s into k3d cluster %s", image, self.k3d_cluster
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to import image %s into k3d cluster %s: %s",
                image,
                self.k3d_cluster,
                exc,
            )
