"""Publish rendered snapshot charts to a GitOps repository for Argo CD.

This module is entirely optional -- it only activates when the environment
variable ``OPENRANGE_GITOPS_ENABLED=true`` is set.  When active, the
:class:`GitOpsPublisher` copies rendered Helm chart artifacts into a Git
repository so that Argo CD can reconcile them into live ranges automatically.

Typical workflow::

    build  ->  render  ->  publish (GitOpsPublisher)  ->  auto-deploy (Argo CD)

Configuration is supplied via :class:`GitOpsConfig`, a Pydantic v2 model that
reads from environment variables prefixed with ``OPENRANGE_GITOPS_``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _gitops_enabled() -> bool:
    """Return True when GitOps publishing is explicitly enabled."""
    return os.getenv("OPENRANGE_GITOPS_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


class GitOpsConfig(BaseModel):
    """Configuration for the GitOps publisher.

    All values can be set via environment variables prefixed with
    ``OPENRANGE_GITOPS_``.  For example ``OPENRANGE_GITOPS_REPO_URL`` maps to
    :pyattr:`repo_url`.
    """

    enabled: bool = Field(
        default=False,
        description="Master switch -- set OPENRANGE_GITOPS_ENABLED=true to activate.",
    )
    repo_url: str = Field(
        default="",
        description="Clone URL of the GitOps repository.",
    )
    branch: str = Field(
        default="main",
        description="Branch to commit rendered charts to.",
    )
    base_path: str = Field(
        default="ranges",
        description="Directory inside the repo where snapshot charts live.",
    )
    work_dir: str = Field(
        default="",
        description=(
            "Local working-copy path. If empty a temporary directory is used."
        ),
    )
    argocd_namespace: str = Field(
        default="argocd",
        description="Kubernetes namespace where Argo CD is installed.",
    )
    sync_timeout: float = Field(
        default=300.0,
        description="Seconds to wait for Argo CD to sync a published snapshot.",
    )
    commit_author_name: str = Field(
        default="open-range",
        description="Git author name for automated commits.",
    )
    commit_author_email: str = Field(
        default="open-range@localhost",
        description="Git author email for automated commits.",
    )

    @classmethod
    def from_env(cls) -> GitOpsConfig:
        """Build a config from ``OPENRANGE_GITOPS_*`` environment variables."""
        prefix = "OPENRANGE_GITOPS_"
        values: dict[str, Any] = {}
        for env_key, env_val in os.environ.items():
            if not env_key.startswith(prefix):
                continue
            field_name = env_key[len(prefix) :].lower()
            if field_name in cls.model_fields:
                values[field_name] = env_val
        return cls(**values)


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------


class GitOpsPublisher:
    """Publish rendered snapshot charts to a GitOps repository for Argo CD.

    Usage::

        cfg = GitOpsConfig.from_env()
        publisher = GitOpsPublisher(
            repo_url=cfg.repo_url,
            branch=cfg.branch,
            base_path=cfg.base_path,
        )
        sha = await publisher.publish("snap-001", Path("/tmp/rendered/snap-001"))
        healthy = await publisher.wait_for_sync("snap-001", timeout=120)
        await publisher.unpublish("snap-001")
    """

    def __init__(
        self,
        repo_url: str,
        branch: str = "main",
        base_path: str = "ranges",
        *,
        work_dir: str | None = None,
        argocd_namespace: str = "argocd",
        commit_author_name: str = "open-range",
        commit_author_email: str = "open-range@localhost",
    ) -> None:
        self._repo_url = repo_url
        self._branch = branch
        self._base_path = base_path
        self._argocd_namespace = argocd_namespace
        self._commit_author_name = commit_author_name
        self._commit_author_email = commit_author_email

        if work_dir:
            self._work_dir = Path(work_dir)
            self._tmp_dir: tempfile.TemporaryDirectory[str] | None = None
        else:
            self._tmp_dir = tempfile.TemporaryDirectory(prefix="openrange-gitops-")
            self._work_dir = Path(self._tmp_dir.name)

        self._repo_ready = False

    @classmethod
    def from_config(cls, config: GitOpsConfig) -> GitOpsPublisher:
        """Construct a publisher from a :class:`GitOpsConfig`."""
        return cls(
            repo_url=config.repo_url,
            branch=config.branch,
            base_path=config.base_path,
            work_dir=config.work_dir or None,
            argocd_namespace=config.argocd_namespace,
            commit_author_name=config.commit_author_name,
            commit_author_email=config.commit_author_email,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def publish(self, snapshot_id: str, artifacts_dir: Path) -> str:
        """Commit rendered chart to GitOps repo.  Returns the commit SHA.

        Parameters
        ----------
        snapshot_id:
            Unique identifier for the snapshot (used as the directory name).
        artifacts_dir:
            Local path containing the rendered Helm chart to publish.

        Returns
        -------
        str
            The Git commit SHA after pushing.
        """
        if not artifacts_dir.is_dir():
            raise FileNotFoundError(
                f"Artifacts directory does not exist: {artifacts_dir}"
            )

        await self._ensure_repo()

        dest = self._work_dir / self._base_path / snapshot_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(artifacts_dir, dest)

        await self._git("add", "--all")

        commit_msg = f"publish snapshot {snapshot_id}"
        await self._git(
            "-c",
            f"user.name={self._commit_author_name}",
            "-c",
            f"user.email={self._commit_author_email}",
            "commit",
            "-m",
            commit_msg,
            "--allow-empty",
        )

        await self._git("push", "origin", self._branch)

        sha = await self._git("rev-parse", "HEAD")
        sha = sha.strip()
        logger.info(
            "Published snapshot %s to %s (commit %s)",
            snapshot_id,
            self._repo_url,
            sha[:12],
        )
        return sha

    async def unpublish(self, snapshot_id: str) -> None:
        """Remove a snapshot's chart from the GitOps repo.

        Commits and pushes the removal so Argo CD prunes the resources.
        """
        await self._ensure_repo()

        dest = self._work_dir / self._base_path / snapshot_id
        if not dest.exists():
            logger.warning(
                "Snapshot %s not found in GitOps repo -- nothing to remove",
                snapshot_id,
            )
            return

        shutil.rmtree(dest)

        await self._git("add", "--all")
        await self._git(
            "-c",
            f"user.name={self._commit_author_name}",
            "-c",
            f"user.email={self._commit_author_email}",
            "commit",
            "-m",
            f"unpublish snapshot {snapshot_id}",
            "--allow-empty",
        )
        await self._git("push", "origin", self._branch)
        logger.info("Unpublished snapshot %s from %s", snapshot_id, self._repo_url)

    async def wait_for_sync(
        self,
        snapshot_id: str,
        timeout: float = 300.0,
    ) -> bool:
        """Wait for Argo CD to sync the application.  Returns True if healthy.

        Polls the Argo CD Application status via ``kubectl`` until the sync is
        complete or *timeout* seconds elapse.
        """
        app_name = f"openrange-{snapshot_id}"
        deadline = asyncio.get_event_loop().time() + timeout
        poll_interval = 5.0

        while asyncio.get_event_loop().time() < deadline:
            try:
                status = await self._get_app_status(app_name)
                sync_status = status.get("sync", {}).get("status", "")
                health_status = status.get("health", {}).get("status", "")

                if sync_status == "Synced" and health_status == "Healthy":
                    logger.info(
                        "Snapshot %s synced and healthy in Argo CD", snapshot_id
                    )
                    return True

                if health_status == "Degraded":
                    logger.warning("Snapshot %s is Degraded in Argo CD", snapshot_id)
                    return False

                logger.debug(
                    "Snapshot %s sync=%s health=%s -- waiting",
                    snapshot_id,
                    sync_status,
                    health_status,
                )
            except Exception:
                logger.debug(
                    "Could not query Argo CD status for %s -- retrying",
                    snapshot_id,
                )

            await asyncio.sleep(poll_interval)

        logger.warning(
            "Timed out waiting for Argo CD sync of snapshot %s after %.0fs",
            snapshot_id,
            timeout,
        )
        return False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _ensure_repo(self) -> None:
        """Clone or update the GitOps repository working copy."""
        if self._repo_ready:
            # Fast-forward existing clone
            try:
                await self._git("fetch", "origin", self._branch)
                await self._git("reset", "--hard", f"origin/{self._branch}")
            except RuntimeError:
                logger.warning("Fast-forward failed; re-cloning")
                self._repo_ready = False

        if not self._repo_ready:
            git_dir = self._work_dir / ".git"
            if git_dir.is_dir():
                # Existing clone -- pull latest
                await self._git("fetch", "origin", self._branch)
                await self._git("checkout", self._branch)
                await self._git("reset", "--hard", f"origin/{self._branch}")
            else:
                # Fresh clone
                await self._run_process(
                    "git",
                    "clone",
                    "--branch",
                    self._branch,
                    "--single-branch",
                    self._repo_url,
                    str(self._work_dir),
                )
            self._repo_ready = True

    async def _git(self, *args: str) -> str:
        """Run a git command inside the working copy."""
        return await self._run_process("git", *args, cwd=self._work_dir)

    @staticmethod
    async def _run_process(
        *args: str,
        cwd: Path | None = None,
        timeout: float = 120.0,
    ) -> str:
        """Run a subprocess asynchronously and return its stdout."""
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"Command timed out: {' '.join(args[:4])}")

        stdout = (stdout_bytes or b"").decode(errors="replace")
        stderr = (stderr_bytes or b"").decode(errors="replace")

        if proc.returncode != 0:
            detail = stderr.strip() or stdout.strip() or "unknown failure"
            raise RuntimeError(
                f"{' '.join(args[:4])}... failed (exit {proc.returncode}): {detail}"
            )
        return stdout

    async def _get_app_status(self, app_name: str) -> dict[str, Any]:
        """Query the Argo CD Application status via kubectl."""
        raw = await self._run_process(
            "kubectl",
            "get",
            "application",
            app_name,
            "-n",
            self._argocd_namespace,
            "-o",
            "json",
        )
        obj = json.loads(raw)
        return obj.get("status", {})

    def __del__(self) -> None:
        if self._tmp_dir is not None:
            try:
                self._tmp_dir.cleanup()
            except Exception:
                pass
