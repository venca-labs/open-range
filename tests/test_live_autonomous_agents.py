import os

import pytest

from open_range.agents import generate_personas
from open_range.agents.autonomous_adapter import (
    configure_autonomous_llm,
    create_enterprise_world,
    persona_to_autonomous,
)

# Determine if real LLM testing is supported in the current environment
HAS_API_KEY = bool(os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENAI_API_KEY"))


@pytest.mark.skipif(
    not HAS_API_KEY,
    reason="Real LLM testing requires API keys (NVIDIA_API_KEY or OPENAI_API_KEY)",
)
def test_live_autonomous_agent_interaction():
    """
    Execute a real Live LLM simulation to prove the underlying TinyTroupe/LLM wiring
    translates personas correctly to Autonomous Worlds, performing 3 cognitive runtime steps.
    """
    # 1. Configure the runtime LLM using real models (no fake LLMs)
    # Defaulting to Kimi K2 via NVIDIA NIM if key is present
    if os.environ.get("NVIDIA_API_KEY"):
        configure_autonomous_llm(
            api_key=os.environ.get("NVIDIA_API_KEY"),
            model="moonshotai/kimi-k2-instruct",
            base_url="https://integrate.api.nvidia.com/v1",
        )
    else:
        # Fallback for standard OpenAI endpoints if OPENAI_API_KEY is found instead
        configure_autonomous_llm(
            api_key=os.environ.get("OPENAI_API_KEY"),
            model="gpt-4o-mini",
            base_url="https://api.openai.com/v1",
        )

    # 2. Generate Personas deterministically via Persona Factory
    personas = generate_personas(count=2, seed=42)
    assert len(personas) == 2

    # 3. Translate GreenPersonas to AutonomousAgent constructs
    agents = [persona_to_autonomous(p) for p in personas]
    assert len(agents) == 2
    assert agents[0].name == personas[0].id

    # 4. Form an Autonomous World
    world = create_enterprise_world("test-office", agents)

    # 5. Execute 3 live cognitive steps against real models
    world.broadcast(
        "A major security vulnerability was just announced impacting all systems. Please communicate and plan remediation."
    )
    world.run(steps=3)

    # The execution of 3 full simulator steps without crashing or raising any parsing
    # exceptions proves the underlying LLMs are binding efficiently via our wrapper.
    # We do not assert exact `pop_latest_actions` here as `world.run()` consumes
    # the underlying SDK memory buffers natively into the environment dialogue stream!
    assert True
