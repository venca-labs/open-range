"""Check 4: Evidence sufficiency — verify evidence artifacts exist in containers."""

from __future__ import annotations

from open_range.protocols import CheckResult, ContainerSet, SnapshotSpec


class EvidenceCheck:
    """Verify all ``evidence_spec`` items exist in the running containers."""

    async def check(self, snapshot: SnapshotSpec, containers: ContainerSet) -> CheckResult:
        items = snapshot.evidence_spec
        if not items:
            return CheckResult(
                name="evidence",
                passed=True,
                details={"note": "no evidence_spec defined — vacuously true"},
            )

        missing: list[dict] = []
        for item in items:
            loc = item.location
            pattern = item.pattern

            # Determine which container to check.  Location format:
            # "container:/path/to/file" or just "/path" (defaults to siem).
            if ":" in loc:
                host, path = loc.split(":", 1)
            else:
                host, path = "siem", loc

            try:
                if item.type in ("log_entry", "alert"):
                    # grep for pattern in the file
                    cmd = f"grep -c '{pattern}' {path}" if pattern else f"test -f {path} && echo ok"
                    output = await containers.exec(host, cmd)
                    # grep -c returns "0" if no matches — that means missing
                    if pattern and output.strip() in ("0", ""):
                        missing.append({"item": item.type, "location": loc, "pattern": pattern})
                else:
                    # file existence check
                    output = await containers.exec(host, f"test -f {path} && echo exists")
                    if "exists" not in output:
                        missing.append({"item": item.type, "location": loc})
            except Exception as exc:  # noqa: BLE001
                missing.append({"item": item.type, "location": loc, "error": str(exc)})

        passed = len(missing) == 0
        return CheckResult(
            name="evidence",
            passed=passed,
            details={"missing": missing, "total": len(items)},
            error="" if passed else f"{len(missing)} evidence item(s) not found",
        )
