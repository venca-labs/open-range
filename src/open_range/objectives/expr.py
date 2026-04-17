"""Shared parsing helpers for objective predicate expressions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PredicateExpr:
    """Normalized parsed representation of a predicate string."""

    raw: str
    name: str
    inner: str = ""


def parse_predicate(predicate: str) -> PredicateExpr:
    raw = predicate.strip()
    if "(" not in raw or ")" not in raw:
        return PredicateExpr(raw=raw, name=raw)
    name, rest = raw.split("(", 1)
    return PredicateExpr(
        raw=raw,
        name=name.strip(),
        inner=rest.rsplit(")", 1)[0].strip(),
    )


def predicate_name(predicate: str) -> str:
    return parse_predicate(predicate).name


def predicate_inner(predicate: str) -> str:
    return parse_predicate(predicate).inner
