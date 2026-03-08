"""Red & Blue agent layer for OpenRange.

Exports:
    - RangeAgent: Protocol for any compatible agent
    - EpisodeResult, EpisodeMetrics: Trajectory/metrics dataclasses
    - LLMRangeAgent: LiteLLM-powered agent (any model)
    - ScriptedAgent, ScriptedRedAgent, ScriptedBlueAgent: Fixed-sequence agents
    - HumanAgent: Interactive stdin/stdout agent
    - run_episode: Orchestration loop
    - evaluate: Multi-episode evaluation harness
    - extract_command: LLM output -> shell command parser
"""

from open_range.agents.protocol import EpisodeMetrics, EpisodeResult, RangeAgent
from open_range.agents.parsing import extract_command
from open_range.agents.scripted_agent import (
    ScriptedAgent,
    ScriptedBlueAgent,
    ScriptedRedAgent,
)
from open_range.agents.human_agent import HumanAgent
from open_range.agents.llm_agent import LLMRangeAgent
from open_range.agents.episode import run_episode
from open_range.agents.eval import evaluate
from open_range.agents.prompts import BLUE_SYSTEM_PROMPT, RED_SYSTEM_PROMPT

__all__ = [
    "RangeAgent",
    "EpisodeResult",
    "EpisodeMetrics",
    "LLMRangeAgent",
    "ScriptedAgent",
    "ScriptedRedAgent",
    "ScriptedBlueAgent",
    "HumanAgent",
    "run_episode",
    "evaluate",
    "extract_command",
    "RED_SYSTEM_PROMPT",
    "BLUE_SYSTEM_PROMPT",
]
