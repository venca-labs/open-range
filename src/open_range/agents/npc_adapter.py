"""NPC components adapter for OpenRange NPC simulation.

Bridges OpenRange's ``GreenPersona`` ↔ NPC Agent's ``TinyPerson`` and
configures Kimi K2 Models (or any OpenAI-compatible endpoint) as the LLM backend.

Usage::

    from open_range.agents.npc_adapter import (
        configure_npc_llm,
        persona_to_npc,
        create_enterprise_world,
    )

    # Point npc framework at Moonshot API / Kimi
    configure_npc_llm(api_key=os.environ["MOONSHOT_API_KEY"])

    # Convert our personas to npc agents
    personas = generate_personas(count=10)
    agents = [persona_to_npc(p) for p in personas]

    # Drop them into a simulated office
    world = create_enterprise_world("acme-corp", agents)
    world.run(steps=5)

Requires ``tinytroupe`` from git for the underlying npc structures::

    pip install "tinytroupe @ git+https://github.com/microsoft/TinyTroupe.git"
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from open_range.agents import _routine_dispatch
from open_range.contracts.runtime import Action
from open_range.contracts.world import GreenPersona

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import
# ---------------------------------------------------------------------------

_npc_available: bool | None = None


def _require_npc_framework() -> None:
    global _npc_available  # noqa: PLW0603
    if _npc_available is True:
        return
    if _npc_available is False:
        raise ImportError(
            "NPC framework dependencies required. Install using uv:\n"
            "  uv sync --extra npc"
        )
    try:
        import tinytroupe.agent  # noqa: F401

        _npc_available = True
    except ImportError:
        _npc_available = False
        raise ImportError(
            "NPC framework dependencies required. Install using uv:\n"
            "  uv sync --extra npc"
        ) from None


# ---------------------------------------------------------------------------
# Component Configuration
# ---------------------------------------------------------------------------


def configure_npc_llm(
    api_key: str | None = None,
    *,
    model: str | None = None,
    base_url: str = "https://integrate.api.nvidia.com/v1/",
) -> None:
    """Configure npc agents to use NVIDIA NIM / Kimi K2 (or any compatible endpoint).

    Args:
        api_key: API key. Falls back to ``NVIDIA_API_KEY`` env var, then ``OPENAI_API_KEY``.
        model: model identifier.  Examples: ``moonshotai/kimi-k2-instruct``, ``meta/llama-3.1-8b-instruct``.
        base_url: API endpoint. Defaults to NVIDIA NIM integration.
    """
    _require_npc_framework()

    key = (
        api_key
        or os.environ.get("NVIDIA_API_KEY")
        or os.environ.get("OPENAI_API_KEY", "")
    )
    if not key:
        logger.warning(
            "No API_KEY found. Set NVIDIA_API_KEY or OPENAI_API_KEY via env vars."
        )

    resolved_model = (
        model or os.environ.get("MODEL_ID") or "moonshotai/kimi-k2-instruct"
    )

    # Set the OpenAI env vars that the npc agents read
    os.environ["OPENAI_API_KEY"] = key

    # Tell the underlying openai client to use the target base URL
    os.environ["OPENAI_BASE_URL"] = base_url

    # Directly inject the model fallback natively into the TinyTroupe global config manager
    try:
        import tinytroupe

        config_manager = getattr(tinytroupe, "config_manager", None)
        if config_manager:
            config_manager.update("model", resolved_model)
            config_manager.update("max_completion_tokens", 4096)
            config_manager.update("max_concurrent_model_calls", 4)
            config_manager.update("timeout", 120.0)
            config_manager.update("waiting_time", 1.0)
            config_manager.update("exponential_backoff_factor", 2.0)
            config_manager.update("max_attempts", 3)

            # Disable memory/consolidation
            config_manager.update("enable_memory_consolidation", False)
            config_manager.update(
                "enable_continuous_contextual_semantic_memory_retrieval", False
            )
    except Exception as e:
        logger.warning(f"Could not apply native config overrides: {e}")

    # Force-reinitialize TinyTroupe's client registry so cached clients
    # pick up the new model/endpoint instead of stale defaults.
    try:
        from tinytroupe import clients as tc

        if "openai" in tc._api_type_to_client:
            tc._api_type_to_client["openai"] = tc.OpenAIClient()
    except Exception as e:
        logger.warning(f"Could not force reinitialize TinyTroupe client: {e}")

    logger.info("Configured NPC Agents → %s: model=%s", base_url, resolved_model)


# ---------------------------------------------------------------------------
# GreenPersona → NPC Spec conversion
# ---------------------------------------------------------------------------

# Department-specific personality fragments
_DEPT_FRAGMENTS: dict[str, dict[str, Any]] = {
    "Engineering": {
        "traits": [
            "You are analytical and detail-oriented.",
            "You prefer structured problem-solving over guesswork.",
            "You enjoy learning about new technologies.",
        ],
        "interests": [
            "Software architecture and clean code.",
            "DevOps practices and automation.",
            "Open source tools and communities.",
        ],
    },
    "IT Security": {
        "traits": [
            "You are vigilant and cautious about potential threats.",
            "You analyze patterns and anomalies instinctively.",
            "You take security incidents seriously and act quickly.",
        ],
        "interests": [
            "Cybersecurity threat intelligence.",
            "Incident response and forensics.",
            "Network security and monitoring tools.",
        ],
    },
    "Finance": {
        "traits": [
            "You are precise and careful with numbers.",
            "You prefer thorough verification before acting.",
            "You are risk-aware in professional decisions.",
        ],
        "interests": [
            "Financial analysis and reporting.",
            "Regulatory compliance.",
            "Spreadsheets and data visualization.",
        ],
    },
    "HR": {
        "traits": [
            "You are empathetic and people-oriented.",
            "You are trusting and assume good intent from colleagues.",
            "You value clear communication and transparency.",
        ],
        "interests": [
            "Employee engagement and culture.",
            "Recruiting and talent management.",
            "Workplace policies and benefits.",
        ],
    },
    "Sales": {
        "traits": [
            "You are outgoing and relationship-driven.",
            "You respond quickly to messages and requests.",
            "You are comfortable with ambiguity and fast decisions.",
        ],
        "interests": [
            "Client relationship management.",
            "Revenue targets and pipeline management.",
            "Networking events and conferences.",
        ],
    },
    "Operations": {
        "traits": [
            "You are systematic and process-oriented.",
            "You value uptime and reliability above all.",
            "You are comfortable with technical tools and systems.",
        ],
        "interests": [
            "Infrastructure management and monitoring.",
            "Process optimization.",
            "IT service management.",
        ],
    },
    "Executive": {
        "traits": [
            "You are strategic and big-picture oriented.",
            "You receive many emails and delegate frequently.",
            "You trust your team and rarely verify details yourself.",
        ],
        "interests": [
            "Company strategy and growth.",
            "Leadership and organizational design.",
            "Industry trends and competitive analysis.",
        ],
    },
}


def persona_to_spec(persona: GreenPersona) -> dict[str, Any]:
    """Convert a ``GreenPersona`` to an NPC Agent JSON agent spec.

    This produces the same format as the framework's `.agent.json` files,
    which can be loaded via the npc agent specification.
    """
    dept = persona.department or "Engineering"
    fragments = _DEPT_FRAGMENTS.get(dept, _DEPT_FRAGMENTS["Engineering"])

    # Security awareness description
    if persona.awareness >= 0.7:
        sec_trait = (
            "You are highly security-conscious and skeptical of unexpected requests."
        )
    elif persona.awareness >= 0.4:
        sec_trait = (
            "You have moderate security awareness and follow basic best practices."
        )
    else:
        sec_trait = "You tend to trust emails and links without much scrutiny."

    # Build routine description
    routine_desc = []
    for task in persona.routine or ("browse_app",):
        kind, svc = _routine_dispatch(task)
        routine_desc.append(f"{task.replace('_', ' ')} ({svc})")

    return {
        "type": "TinyPerson",
        "persona": {
            "name": persona.id,
            "age": 30,  # placeholder
            "occupation": {
                "title": persona.role,
                "organization": f"{dept} Department",
                "description": (
                    f"You are a {persona.role} in the {dept} department at a "
                    f"mid-size enterprise SaaS company.  Your workstation is "
                    f"{persona.home_host}.  Your typical daily tasks include: "
                    f"{', '.join(routine_desc)}. "
                    "When you need to take concrete technical actions (e.g., browsing a web application, sending an email, or executing a shell command on your computer), "
                    "you MUST embed a JSON block in your thought or dialogue exactly like this: "
                    '`{"kind": "mail", "service": "svc-email", "to": "admin"}` or `{"kind": "shell", "command": "whoami"}`.'
                ),
            },
            "personality": {
                "traits": fragments["traits"] + [sec_trait],
            },
            "preferences": {
                "interests": fragments["interests"],
            },
            "skills": [
                f"Department: {dept}",
                f"Security awareness: {persona.awareness:.0%}",
                f"Primary workstation: {persona.home_host}",
            ],
        },
    }


def persona_to_npc(persona: GreenPersona) -> Any:
    """Create a live NPC Agent instance from a ``GreenPersona``."""
    _require_npc_framework()
    from tinytroupe.agent import TinyPerson as NPCPersona

    spec = persona_to_spec(persona)

    agent = NPCPersona(name=persona.id)

    # Use define() to set persona fields
    p = spec["persona"]
    if "occupation" in p:
        agent.define("occupation", p["occupation"])
    if "personality" in p:
        agent.define("personality", p["personality"])
    if "preferences" in p:
        agent.define("preferences", p["preferences"])
    if "skills" in p:
        agent.define("skills", p["skills"])

    # Tightly couple OpenRange native routines into TinyTroupe's native goal engine
    daily_tasks = persona.routine or ["browse_app"]
    parsed_tasks = [task.replace("_", " ") for task in daily_tasks]
    agent.internalize_goal(
        f"Your primary objective today is to balance and execute your typical daily tasks: {', '.join(parsed_tasks)}."
    )

    return agent


# ---------------------------------------------------------------------------
# Enterprise world factory
# ---------------------------------------------------------------------------


def create_enterprise_world(
    company_name: str,
    agents: list[Any],
) -> Any:
    """Create an NPC World populated with enterprise NPC agents.

    The world simulates an office environment where agents can
    observe events and interact with each other.
    """
    _require_npc_framework()
    from tinytroupe.environment import TinyWorld as NPCWorld

    world = NPCWorld(
        name=f"{company_name}-office",
        agents=agents,
    )
    # Tightly couple agents into a shared social network allowing native interactions
    world.make_everyone_accessible()
    return world


# ---------------------------------------------------------------------------
# Parse NPC Agent action → OpenRange Action
# ---------------------------------------------------------------------------

_ACTION_PATTERNS = [
    (
        re.compile(r"(?:report|notify|alert|escalate).*(?:IT|security|admin)", re.I),
        "shell",
        "svc-siem",
    ),
    (
        re.compile(r"(?:reset|change|rotate).*(?:password|credential)", re.I),
        "control",
        "svc-idp",
    ),
    (
        re.compile(r"(?:check|read|send|open).*(?:email|mail)", re.I),
        "mail",
        "svc-email",
    ),
    (re.compile(r"(?:chat|message|talk|communicate|warn)", re.I), "chat", "svc-web"),
    (
        re.compile(r"(?:share|upload|send).*(?:document|file)", re.I),
        "document_share",
        "svc-fileshare",
    ),
    (
        re.compile(r"(?:browse|navigate|open).*(?:app|site|page)", re.I),
        "api",
        "svc-web",
    ),
]


def parse_action(persona_id: str, action_text: str) -> Action:
    """Parse an NPC Agent's natural-language action into an OpenRange Action."""

    # TinyTroupe often nests the underlying message payload recursively in dictionaries
    if isinstance(action_text, dict):
        action_text = action_text.get("action", {}).get("msg", str(action_text))

    text = str(action_text).strip()

    # Peel off the outer JSON wrapper if the LLM output the entire cognitive block purely as a string
    try:
        outer_data = json.loads(text)
        if isinstance(outer_data, dict) and "action" in outer_data:
            inner_action = outer_data["action"]
            if isinstance(inner_action, dict) and "msg" in inner_action:
                text = str(inner_action["msg"]).strip()
    except (json.JSONDecodeError, ValueError):
        pass

    # Try JSON embedded in the response natively
    try:
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            kind = data.get("kind", data.get("action", "api"))
            if kind not in {
                "shell",
                "api",
                "mail",
                "chat",
                "document_share",
                "voice",
                "control",
                "submit_finding",
                "sleep",
            }:
                kind = "api"
            return Action(
                actor_id=persona_id,
                role="green",
                kind=kind,
                payload={k: v for k, v in data.items() if k not in ("kind", "action")},
            )
    except (json.JSONDecodeError, ValueError):
        pass

    # Pattern match
    for pattern, kind, service in _ACTION_PATTERNS:
        if pattern.search(text):
            return Action(
                actor_id=persona_id,
                role="green",
                kind=kind,
                payload={"service": service, "raw": text[:200]},
            )

    # Fallback: generic browse
    return Action(
        actor_id=persona_id,
        role="green",
        kind="api",
        payload={"service": "svc-web", "routine": "browse_app", "raw": text[:200]},
    )
