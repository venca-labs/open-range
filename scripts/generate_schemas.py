"""Generate checked-in JSON schema files for the core models."""

from __future__ import annotations

import json
from pathlib import Path

from open_range.admission import ValidatorReport, ReferenceBundle
from open_range.manifest import EnterpriseSaaSManifest


def _write_schema(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    schema_dir = root / "schemas"
    package_schema_dir = root / "src" / "open_range" / "_resources" / "schemas"
    payloads = {
        "manifest.schema.json": EnterpriseSaaSManifest.model_json_schema(),
        "validator_report.schema.json": ValidatorReport.model_json_schema(),
        "reference_bundle.schema.json": ReferenceBundle.model_json_schema(),
    }
    for name, payload in payloads.items():
        _write_schema(schema_dir / name, payload)
        _write_schema(package_schema_dir / name, payload)


if __name__ == "__main__":
    main()
