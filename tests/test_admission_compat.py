from __future__ import annotations

import open_range.admission as admission
from open_range.admission.models import ProbeKind, ReferenceRole, ReportMode


def test_admission_package_keeps_legacy_type_aliases() -> None:
    assert admission.ReferenceRole is ReferenceRole
    assert admission.ProbeKind is ProbeKind
    assert admission.ReportMode is ReportMode
