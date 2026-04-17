"""Live security probes for Kind-backed admission."""

from __future__ import annotations

import shlex

from open_range.admission.models import ValidatorCheckReport
from open_range.contracts.world import ServiceSpec, WorldIR
from open_range.support.async_utils import run_async

_DB_MTLS_CLIENT_CONTAINER = "db-client-mtls"
_DB_MTLS_CLIENT_CONFIG = "/etc/mysql/conf.d/openrange-client-mtls.cnf"
_DB_MTLS_FAILURE_MARKERS = (
    "access denied",
    "require x509",
    "x509",
    "certificate",
    "ssl",
    "tls",
    "1045",
)


def check_live_db_mtls(world: WorldIR, release) -> ValidatorCheckReport:
    mtls = world.security_runtime.mtls
    if not mtls or not mtls.get("enabled"):
        return ValidatorCheckReport(
            name="live_db_mtls",
            passed=True,
            details={"note": "mTLS not enabled"},
        )

    web_client = _db_mtls_web_client(world)
    if web_client is None:
        return ValidatorCheckReport(
            name="live_db_mtls",
            passed=True,
            details={"note": "no built-in web client depends on svc-db"},
        )

    positive_cmd = _db_mtls_positive_cmd()
    positive_result = run_async(
        release.pods.exec(
            web_client.id,
            positive_cmd,
            timeout=15.0,
            container=_DB_MTLS_CLIENT_CONTAINER,
        )
    )

    negative_cmd = _db_mtls_negative_cmd()
    negative_result = run_async(
        release.pods.exec("sandbox-red", negative_cmd, timeout=15.0)
    )

    failures = _db_mtls_failures(positive_result, negative_result)
    return ValidatorCheckReport(
        name="live_db_mtls",
        passed=not failures,
        details={
            "web_client": web_client.id,
            "positive_runner": web_client.id,
            "positive_container": _DB_MTLS_CLIENT_CONTAINER,
            "positive_cmd": positive_cmd,
            "positive_stdout": positive_result.stdout.strip(),
            "positive_stderr": positive_result.stderr.strip(),
            "negative_runner": "sandbox-red",
            "negative_cmd": negative_cmd,
            "negative_stdout": negative_result.stdout.strip(),
            "negative_stderr": negative_result.stderr.strip(),
        },
        error="; ".join(failures),
    )


def _db_mtls_web_client(world: WorldIR) -> ServiceSpec | None:
    for service in world.services:
        if service.kind == "web_app" and "svc-db" in service.dependencies:
            return service
    return None


def _db_mtls_positive_cmd() -> str:
    return f'mysql --defaults-extra-file={_DB_MTLS_CLIENT_CONFIG} -Nse "SELECT 1;"'


def _db_mtls_negative_cmd() -> str:
    return shlex.join(
        [
            "mysql",
            "--protocol=TCP",
            "--connect-timeout=5",
            "-h",
            "svc-db",
            "-uapp",
            "-papp-pass",
            "app",
            "-Nse",
            "SELECT 'openrange-db-mtls-ok';",
        ]
    )


def _db_mtls_failures(positive_result, negative_result) -> list[str]:
    failures: list[str] = []
    if not positive_result.ok:
        failures.append(
            f"positive_path:{positive_result.stderr or positive_result.stdout or 'failed'}"
        )
    if negative_result.ok:
        failures.append("no_cert_path:unexpected_success")
    elif not _negative_result_reflects_mtls_enforcement(negative_result):
        failures.append(
            f"no_cert_path:unexpected_failure_mode:{negative_result.stderr or negative_result.stdout or 'failed'}"
        )
    return failures


def _negative_result_reflects_mtls_enforcement(result) -> bool:
    output = (
        "\n".join(part for part in (result.stdout, result.stderr) if part)
        .strip()
        .lower()
    )
    return any(marker in output for marker in _DB_MTLS_FAILURE_MARKERS)
