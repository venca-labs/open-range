"""NPC persistent memory graph.

Lightweight implementation of the memory architecture from Park et al.
(2023) "Generative Agents: Interactive Simulacra of Human Behavior",
extended to store entity-relationship triples rather than flat text.

Each memory entry is a directed triple:

    (subject, relation, object_)

For example:
    ("janet.liu", "received_phishing_from", "attacker@evil.com")
    ("janet.liu", "responded_with",         "report_to_IT")
    ("janet.liu", "browsed",                "/portal/dashboard")

This structure enables entity-level retrieval: query for all memories
involving a specific actor, service, or action type by matching against
any part of the triple.

Retrieval ranks entries by a weighted combination of:

  recency    — exponential decay since creation
  importance — normalized 0–1 from the 1–10 score
  relevance  — Jaccard overlap of query terms against tags +
               tokenised triple fields

No LLM is required for storage or retrieval; the DailyPlanner uses the
LLM only for the optional reflection step.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field


@dataclass
class MemoryEntry:
    """A single NPC memory stored as an entity-relationship triple."""

    subject: str   # who/what initiated the event   e.g. "janet.liu"
    relation: str  # the relationship or action      e.g. "received_phishing_from"
    object_: str   # target or outcome               e.g. "attacker@evil.com"
    importance: float  # 1 (trivial) – 10 (critical)
    timestamp: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    @property
    def content(self) -> str:
        """Human-readable rendering of the triple."""
        return f"{self.subject} {self.relation} {self.object_}"

    def _entity_tokens(self) -> set[str]:
        """Lowercase tokens derived from all three triple fields.

        Splits on ``._-`` so that e.g. ``janet.liu`` contributes both
        ``janet`` and ``liu``, and ``received_phishing_from`` contributes
        ``received``, ``phishing``, and ``from``.
        """
        tokens: set[str] = set()
        for val in (self.subject, self.relation, self.object_):
            for part in val.replace(".", " ").replace("_", " ").replace("-", " ").lower().split():
                tokens.add(part)
        return tokens

    def recency_score(self, now: float, decay: float = 0.9992) -> float:
        """Exponential decay since creation (1.0 = just happened).

        Default decay constant keeps a 10-min-old memory at ~0.95 and a
        2-hour-old memory at ~0.65, matching typical episode durations.
        """
        elapsed_s = max(0.0, now - self.timestamp)
        return math.pow(decay, elapsed_s)

    def relevance_score(self, query_tags: list[str]) -> float:
        """Jaccard overlap of query terms against tags and triple tokens.

        Matching against the tokenised triple fields (subject, relation,
        object_) means queries like ``["phishing", "janet"]`` will surface
        memories involving Janet and phishing even without explicit tags.
        """
        if not query_tags:
            return 0.0
        q = {t.lower() for t in query_tags}
        m = {t.lower() for t in self.tags} | self._entity_tokens()
        if not m:
            return 0.0
        return len(q & m) / len(q | m)

    def retrieval_score(
        self,
        now: float,
        query_tags: list[str],
        *,
        w_recency: float = 1.0,
        w_importance: float = 1.0,
        w_relevance: float = 1.0,
    ) -> float:
        """Composite retrieval score (higher = more relevant to surface)."""
        return (
            w_recency * self.recency_score(now)
            + w_importance * (self.importance / 10.0)
            + w_relevance * self.relevance_score(query_tags)
        )


class MemoryStream:
    """Persistent in-process memory graph for a single NPC persona.

    Backed by a plain list; suitable for episode-length lifetimes (hundreds
    of entries).  Uses eviction of lowest-importance entry when at capacity.
    """

    def __init__(self, max_size: int = 150) -> None:
        self._memories: list[MemoryEntry] = []
        self.max_size = max_size
        self._reflection_pointer: int = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add(
        self,
        subject: str,
        relation: str,
        object_: str,
        importance: float,
        tags: list[str] | None = None,
    ) -> None:
        """Add a triple memory, evicting the least important entry if at capacity."""
        entry = MemoryEntry(
            subject=subject,
            relation=relation,
            object_=object_,
            importance=max(1.0, min(10.0, importance)),
            tags=list(tags or []),
        )
        with self._lock:
            self._memories.append(entry)
            if len(self._memories) > self.max_size:
                # Evict the entry with the lowest importance (excluding the new one)
                victim = min(range(len(self._memories) - 1), key=lambda i: self._memories[i].importance)
                self._memories.pop(victim)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query_tags: list[str],
        top_k: int = 5,
        *,
        w_recency: float = 1.0,
        w_importance: float = 1.0,
        w_relevance: float = 1.0,
    ) -> list[MemoryEntry]:
        """Return top-k memories ranked by recency + importance + relevance."""
        now = time.time()
        with self._lock:
            scored = sorted(
                self._memories,
                key=lambda m: m.retrieval_score(
                    now, query_tags,
                    w_recency=w_recency,
                    w_importance=w_importance,
                    w_relevance=w_relevance,
                ),
                reverse=True,
            )
            return scored[:top_k]

    def recent(self, n: int = 5) -> list[MemoryEntry]:
        """Return the n most recent memories in chronological order."""
        with self._lock:
            return sorted(self._memories, key=lambda m: m.timestamp)[-n:]

    def to_summary_list(self, n: int = 10) -> list[str]:
        """Return human-readable triple strings for the n most recent memories."""
        return [m.content for m in self.recent(n)]

    def to_context_list(self, n: int = 10) -> list[dict[str, str]]:
        """Return structured triple dicts for the n most recent memories.

        Use this when building LLM payloads — the structured format is
        easier for the model to parse than free-form strings.
        """
        return [
            {"subject": m.subject, "relation": m.relation, "object": m.object_}
            for m in self.recent(n)
        ]

    # ------------------------------------------------------------------
    # Reflection support
    # ------------------------------------------------------------------

    def needs_reflection(self, threshold: int = 10) -> bool:
        """True when enough new memories have accumulated to warrant reflection."""
        with self._lock:
            return (len(self._memories) - self._reflection_pointer) >= threshold

    def take_for_reflection(self) -> list[MemoryEntry]:
        """Return unprocessed memories and advance the reflection pointer."""
        with self._lock:
            unprocessed = self._memories[self._reflection_pointer:]
            self._reflection_pointer = len(self._memories)
            return unprocessed

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._memories)

    def __repr__(self) -> str:
        return f"MemoryStream({len(self._memories)} entries)"
