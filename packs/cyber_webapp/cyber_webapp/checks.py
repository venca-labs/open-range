"""Feasibility (admission probe) and episode (verifier) check sources.

Both are emitted as Python source strings the orchestrator exec's in a
sandboxed namespace (no builtins). Constraints on this code:
  - No ``bool()``, ``isinstance``, etc. — exec'd without builtins
  - Reads inputs from the supplied mapping; returns a mapping

The feasibility source is rendered per build with the world's flag
value baked in (the probe rubber-stamps "world is up + flag exists"
since exploit-driven probes are out of scope for v1 — the static
``OraclePathExistsConstraint`` covers structural feasibility).

The verifier source is constant: compares ``state['result']['flag']``
against ``state['world']['flag']`` for the agent's submitted result.
"""

from __future__ import annotations

import json

from openrange import PackError, WorldGraph


def flag_from_graph(graph: WorldGraph | None) -> str:
    """Pull the flag value out of a built world graph.

    The procedural sampler always emits exactly one ``secret`` node of
    kind ``"flag"`` whose ``value_ref`` carries the string. Raises if
    no flag is present (the orchestrator should have rejected the
    graph before reaching this point).
    """
    if graph is None:
        raise PackError("cannot derive flag from absent world graph")
    for node in graph.nodes:
        if node.type == "secret" and node.attrs.get("kind") == "flag":
            return str(node.attrs["value_ref"])
    raise PackError("world graph has no flag-kind secret")


def render_feasibility_source(flag_value: str) -> str:
    """Emit a feasibility-probe source with the flag value baked in.

    The probe simulates the agent's success: it confirms the realized
    service is up, then returns ``result.flag`` set to the world's
    actual flag. The orchestrator overlays ``probe['world']`` with the
    pack's projected world dict; the verifier compares the two and
    passes admission.

    This is an *upper bound* on agent feasibility — it doesn't prove
    an agent can find the flag, only that one *exists* and that the
    world serves traffic. Static feasibility (oracle path exists in
    the graph) is covered by ``OraclePathExistsConstraint``.
    """
    return (
        "def admission_state(interface):\n"
        "    base_url = interface['base_url']\n"
        "    body = interface['http_get']('/')\n"
        "    return {\n"
        "        'result': {'flag': " + json.dumps(flag_value) + "},\n"
        "        'world': {'flag': " + json.dumps(flag_value) + "},\n"
        "        'requests': [],\n"
        "        'probe_status': 'ok' if body is not None else 'down',\n"
        "        'base_url': base_url,\n"
        "    }\n"
    )


# After the agent's episode, check ``state['result']['flag']`` against
# ``state['world']['flag']``. Verifier source is exec'd inside a sandbox
# without builtins, so no ``bool()`` / ``isinstance`` / etc.
VERIFIER_SOURCE = """
def verify(state):
    result = state.get("result") or {}
    world = state.get("world") or {}
    submitted = result.get("flag")
    expected = world.get("flag")
    passed = submitted is not None and submitted != "" and submitted == expected
    return {
        "passed": passed,
        "score": 1.0 if passed else 0.0,
        "details": {
            "submitted": submitted,
            "expected": expected,
        },
    }
"""
