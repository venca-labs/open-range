"""Installable example modules."""

from __future__ import annotations

__all__ = ["run_demo", "run_bootstrap_demo"]


def __getattr__(name: str):
    if name == "run_demo":
        from open_range.examples.demo import run_demo

        return run_demo
    if name == "run_bootstrap_demo":
        from open_range.examples.bootstrap import run_bootstrap_demo

        return run_bootstrap_demo
    raise AttributeError(name)
