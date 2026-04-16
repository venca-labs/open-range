from __future__ import annotations

import open_range.admission as admission
import open_range.admit as admit
from open_range.admission.models import ProbeKind, ReferenceRole, ReportMode
from open_range.admission.registry import CheckFunc


def test_admission_package_keeps_legacy_type_aliases() -> None:
    assert admission.ReferenceRole is ReferenceRole
    assert admission.ProbeKind is ProbeKind
    assert admission.ReportMode is ReportMode


def test_admit_shim_keeps_checkfunc_alias() -> None:
    assert admit.CheckFunc is CheckFunc
