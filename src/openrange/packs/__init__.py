"""Bundled cyber pack implementations.

Each pack lives in its own folder under this module:

  - ``cyber_webapp_offense_v1/`` — procedural builder + codegen,
    multi-node ontology, NPCs
  - ``cyber_vulnerabilities/``   — shared vuln catalog used by v1+

Pack classes are re-exported here so the
``[project.entry-points."openrange.packs"]`` lines in pyproject.toml
can resolve them through ``openrange.packs:<ClassName>``. New
built-in packs add an import + entry-point line; everything else
lives in the pack folder.
"""

from __future__ import annotations

from openrange.packs.cyber_webapp_offense_v1 import CyberWebappOffenseV1Pack

__all__ = ["CyberWebappOffenseV1Pack"]
