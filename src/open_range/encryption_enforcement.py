"""Check: Encryption enforcement -- validates envelope encryption compliance.

Advisory check that verifies envelope encryption config files are present
and consistent in the rendered artifact directory.  This check is advisory:
failures log warnings but never block admission, since envelope encryption
is an optional layer.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from open_range.admission import ValidatorCheckReport
from open_range.snapshot import KindArtifacts
from open_range.world_ir import WorldIR

logger = logging.getLogger(__name__)

_BUNDLE_REQUIRED_KEYS = {"ciphertext", "nonce", "wrapped_dek", "aad"}


def check_encryption_enforcement(
    world: WorldIR,
    artifacts: KindArtifacts,
    reference_bundle: object = None,
) -> ValidatorCheckReport:
    """Validate envelope encryption config in rendered artifacts.

    Matches v1's ``CheckFunc`` signature so it can be registered as an
    advisory admission check.
    """
    security_dir = Path(artifacts.render_dir) / "security" / "encryption"
    config_path = security_dir / "config.json"
    dek_path = security_dir / "wrapped_dek.json"

    if not config_path.exists():
        return ValidatorCheckReport(
            name="encryption_enforcement",
            passed=True,
            advisory=True,
            details={"note": "envelope encryption not configured -- vacuously passes"},
        )

    issues: list[str] = []

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return ValidatorCheckReport(
            name="encryption_enforcement",
            passed=False,
            advisory=True,
            details={"error": f"cannot read encryption config: {exc}"},
        )

    if not config.get("enabled"):
        return ValidatorCheckReport(
            name="encryption_enforcement",
            passed=True,
            advisory=True,
            details={"note": "envelope encryption not enabled -- vacuously passes"},
        )

    encrypted_paths = config.get("encrypted_paths", [])
    if not encrypted_paths:
        issues.append("encryption enabled but no encrypted_paths listed")

    # Validate wrapped DEK file
    if dek_path.exists():
        try:
            dek_data = json.loads(dek_path.read_text(encoding="utf-8"))
            if not isinstance(dek_data, dict):
                issues.append("wrapped_dek.json is not a JSON object")
            else:
                for ref_id, bundle in dek_data.items():
                    if isinstance(bundle, dict) and not _BUNDLE_REQUIRED_KEYS.issubset(
                        bundle.keys()
                    ):
                        issues.append(
                            f"encrypted bundle for '{ref_id}' missing required keys"
                        )
        except json.JSONDecodeError:
            issues.append("wrapped_dek.json is not valid JSON")
    elif encrypted_paths:
        issues.append("encrypted_paths defined but wrapped_dek.json not found")

    passed = len(issues) == 0
    return ValidatorCheckReport(
        name="encryption_enforcement",
        passed=passed,
        advisory=True,
        details={"encrypted_paths": encrypted_paths, "issues": issues},
        error="" if passed else "; ".join(issues),
    )
