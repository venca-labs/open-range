"""Check 5: Reward grounding — verify flag values exist at expected paths."""

from __future__ import annotations

import re
import shlex

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _parse_db_path(path: str) -> tuple[str, str, str] | None:
    """Parse a DB flag path like ``db:database.table.column``.

    Returns ``(database, table, column)`` or *None* if the path is not a
    valid DB reference.
    """
    prefix = path.split(":", 1)
    if len(prefix) != 2:
        return None
    scheme, rest = prefix
    if scheme not in ("db", "mysql"):
        return None
    parts = rest.split(".")
    if len(parts) != 3:
        return None
    if not all(_IDENTIFIER_RE.fullmatch(part) for part in parts):
        return None
    return parts[0], parts[1], parts[2]


def _mysql_root_password(snapshot: SnapshotSpec) -> str:
    """Return the MySQL root password to use for validator DB checks."""
    topology = snapshot.topology
    if isinstance(topology, dict):
        value = topology.get("mysql_root_password")
        if isinstance(value, str) and value:
            return value
    return "root"


class RewardGroundingCheck:
    """For every declared flag, verify its value exists at the expected
    location.  File-based flags are checked via ``cat``.  DB-stored flags
    (``db:<database>.<table>.<column>``) are verified via a MySQL query.
    """

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        flags = snapshot.flags
        if not flags:
            return CheckResult(
                name="reward_grounding",
                passed=False,
                error="no flags defined in snapshot",
            )

        bad: list[dict] = []
        for flag in flags:
            host = flag.host
            path = flag.path

            # --- DB-stored flags -------------------------------------------
            if path.startswith(("db:", "mysql:")):
                # Deployment artifacts like "db:sql" are not flag locations.
                db_ref = _parse_db_path(path)
                if db_ref is None:
                    if path in {"db:sql", "mysql:sql"}:
                        continue
                    bad.append({
                        "flag": flag.id,
                        "error": f"invalid db flag path format: {path}",
                    })
                    continue

                database, table, column = db_ref
                query = f"SELECT `{column}` FROM `{database}`.`{table}` LIMIT 1"
                mysql_pwd = _mysql_root_password(snapshot)
                mysql_cmd = (
                    f"MYSQL_PWD={shlex.quote(mysql_pwd)} "
                    "mysql -u root -N "
                    f"-e {shlex.quote(query)}"
                )
                try:
                    output = await containers.exec(host, mysql_cmd)
                    output = output.strip()
                except Exception as exc:  # noqa: BLE001
                    bad.append({"flag": flag.id, "error": str(exc)})
                    continue

                if flag.value not in output:
                    bad.append({
                        "flag": flag.id,
                        "expected": flag.value,
                        "got_snippet": output[:200],
                    })
                continue

            # --- Filesystem flags ------------------------------------------
            if "/" not in path:
                # Non-filesystem, non-DB flag path we don't understand.
                bad.append({
                    "flag": flag.id,
                    "error": f"unknown flag path format: {path}",
                })
                continue

            try:
                output = await containers.exec(host, f"cat -- {shlex.quote(path)}")
                output = output.strip()
            except Exception as exc:  # noqa: BLE001
                bad.append({"flag": flag.id, "error": str(exc)})
                continue

            if flag.value not in output:
                bad.append({
                    "flag": flag.id,
                    "expected": flag.value,
                    "got_snippet": output[:200],
                })

        passed = len(bad) == 0
        return CheckResult(
            name="reward_grounding",
            passed=passed,
            details={"results": bad, "total_flags": len(flags)},
            error="" if passed else f"{len(bad)} flag(s) not found at expected location",
        )
