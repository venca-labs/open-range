"""Prometheus-based reward signals for Blue agent training.

Provides a ``PrometheusRewardDataSource`` that queries a Prometheus server
for metrics used to compute supplementary reward signals.  These signals
can complement OpenRange's objective/event-grounded scoring or feed into an
external training harness.

The module is entirely optional.  When Prometheus is unreachable, every
method returns a safe default value so training can proceed without the
monitoring stack.

Example usage::

    source = PrometheusRewardDataSource()
    avail = await source.service_availability("web")
    detection = await source.detection_score(window_minutes=5)
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class PrometheusConfig(BaseModel):
    """Configuration for the Prometheus reward data source."""

    url: str = Field(
        default="http://prometheus.monitoring:9090",
        description="Base URL of the Prometheus server.",
    )
    timeout_s: float = Field(
        default=5.0,
        description="HTTP request timeout in seconds.",
    )
    enabled: bool = Field(
        default=True,
        description="Master switch.  When False, all queries return defaults.",
    )
    default_availability: float = Field(
        default=1.0,
        description="Default availability score when Prometheus is unavailable.",
    )
    default_detection: float = Field(
        default=0.0,
        description="Default detection score when Prometheus is unavailable.",
    )
    alert_label_selector: str = Field(
        default='team="openrange"',
        description="PromQL label selector for OpenRange alerts.",
    )


# ---------------------------------------------------------------------------
# Data source
# ---------------------------------------------------------------------------


class PrometheusRewardDataSource:
    """Query Prometheus for Blue agent reward signals.

    All public methods are async and safe to call when Prometheus is
    unavailable -- they log a warning and return a configurable default.
    """

    def __init__(
        self,
        prometheus_url: str = "http://prometheus.monitoring:9090",
        *,
        config: PrometheusConfig | None = None,
    ) -> None:
        if config is not None:
            self._config = config
        else:
            self._config = PrometheusConfig(url=prometheus_url)

    # -- public API --------------------------------------------------------

    async def service_availability(self, service: str) -> float:
        """Return a 0.0-1.0 availability score based on ``up`` metrics.

        Queries ``up{job=~".*<service>.*"}`` and returns the fraction of
        targets that are up.  Returns ``default_availability`` on error.
        """
        if not self._config.enabled:
            return self._config.default_availability

        promql = f'up{{job=~".*{service}.*"}}'
        try:
            results = await self.query(promql)
        except Exception:
            return self._config.default_availability

        if not results:
            return self._config.default_availability

        up_count = sum(1 for r in results if self._scalar(r) == 1.0)
        return up_count / len(results)

    async def detection_score(self, window_minutes: int = 5) -> float:
        """Return a 0.0-1.0 score based on alerts fired vs expected.

        Queries ``ALERTS{<label_selector>, alertstate="firing"}`` and
        computes a bounded score:
            ``min(firing_count / max(expected, 1), 1.0)``

        A higher score means more alerts are firing -- which rewards the
        Blue agent for having detection coverage.

        Returns ``default_detection`` on error.
        """
        if not self._config.enabled:
            return self._config.default_detection

        selector = self._config.alert_label_selector
        promql = f'ALERTS{{{selector}, alertstate="firing"}}'
        try:
            results = await self.query(promql)
        except Exception:
            return self._config.default_detection

        firing = len(results)
        if firing == 0:
            return 0.0

        # Normalise: assume 4 expected alert rules as baseline from
        # alert-rules.yaml (service-down, error-rate, unauth, suspicious).
        expected = 4
        return min(firing / expected, 1.0)

    async def error_rate(self, namespace: str = "openrange-.*") -> float:
        """Return the aggregate HTTP 5xx error rate across a namespace.

        Returns 0.0 on error or when no data is available.
        """
        if not self._config.enabled:
            return 0.0

        promql = (
            f'sum(rate(http_requests_total{{namespace=~"{namespace}",status=~"5.."}}[5m]))'
            f" / "
            f'sum(rate(http_requests_total{{namespace=~"{namespace}"}}[5m]))'
        )
        try:
            results = await self.query(promql)
        except Exception:
            return 0.0

        if not results:
            return 0.0

        return max(0.0, min(self._scalar(results[0]), 1.0))

    async def unauthorized_request_count(
        self,
        namespace: str = "openrange-.*",
        window_minutes: int = 5,
    ) -> int:
        """Return count of 401/403 responses in the given window."""
        if not self._config.enabled:
            return 0

        promql = (
            f"sum(increase(http_requests_total"
            f'{{namespace=~"{namespace}",status=~"401|403"}}'
            f"[{window_minutes}m]))"
        )
        try:
            results = await self.query(promql)
        except Exception:
            return 0

        if not results:
            return 0

        return int(self._scalar(results[0]))

    async def pod_restart_count(
        self,
        namespace: str = "openrange-.*",
        window_minutes: int = 15,
    ) -> int:
        """Return total pod restart count in the given window."""
        if not self._config.enabled:
            return 0

        promql = (
            f"sum(increase(kube_pod_container_status_restarts_total"
            f'{{namespace=~"{namespace}"}}'
            f"[{window_minutes}m]))"
        )
        try:
            results = await self.query(promql)
        except Exception:
            return 0

        if not results:
            return 0

        return int(self._scalar(results[0]))

    async def query(self, promql: str) -> list[dict[str, Any]]:
        """Execute a PromQL instant query and return the result vector.

        Returns an empty list on any error.

        Each element is a dict with ``"metric"`` and ``"value"`` keys, e.g.::

            {"metric": {"__name__": "up", "job": "web"}, "value": [1710000000, "1"]}
        """
        try:
            import httpx
        except ImportError:
            logger.warning(
                "httpx is not installed; Prometheus queries are disabled. "
                "Install it with: pip install httpx"
            )
            return []

        url = f"{self._config.url.rstrip('/')}/api/v1/query"
        try:
            async with httpx.AsyncClient(timeout=self._config.timeout_s) as client:
                resp = await client.get(url, params={"query": promql})
                resp.raise_for_status()
                body = resp.json()
        except httpx.HTTPError as exc:
            logger.warning("Prometheus query failed: %s", exc)
            return []
        except Exception as exc:
            logger.warning("Prometheus query error: %s", exc)
            return []

        if body.get("status") != "success":
            logger.warning(
                "Prometheus returned non-success status: %s",
                body.get("error", body.get("status")),
            )
            return []

        data = body.get("data", {})
        return data.get("result", [])

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _scalar(result: dict[str, Any]) -> float:
        """Extract the scalar float from a Prometheus instant-query result."""
        try:
            value = result.get("value", [None, "0"])
            return float(value[1])
        except (IndexError, TypeError, ValueError):
            return 0.0
