"""Rollout function for TRL GRPOTrainer integration.

DEFERRED -- this is a stub. The environment must work first; anyone can
plug in TRL/Unsloth/SkyRL later via this rollout_func.

Usage with GRPOTrainer::

    from open_range.training.rollout import rollout_func
    trainer = GRPOTrainer(
        ...,
        rollout_func=rollout_func,
    )
"""

from __future__ import annotations

from typing import Any, Callable, Protocol


class AgentCallable(Protocol):
    """Minimal agent interface for rollout."""

    def __call__(self, observation: Any) -> Any: ...


async def rollout_func(
    env: Any,
    agent: AgentCallable,
    num_steps: int = 100,
    mode: str = "red",
) -> dict[str, Any]:
    """Run a single episode rollout.

    Args:
        env: An OpenRange environment (RangeEnvironment or EnvClient).
        agent: Callable that takes an observation and returns an action.
        num_steps: Maximum steps per episode.
        mode: Agent mode ("red" or "blue").

    Returns:
        Dictionary with episode summary: observations, actions, rewards,
        total_reward, steps, done.
    """
    obs = env.reset()
    trajectory: list[dict[str, Any]] = []
    total_reward = 0.0

    for step in range(num_steps):
        action = agent(obs)

        # Ensure mode is set
        if hasattr(action, "mode"):
            action.mode = mode

        obs = env.step(action)

        reward = getattr(obs, "reward", 0.0) or 0.0
        total_reward += reward

        trajectory.append({
            "step": step,
            "action": action,
            "observation": obs,
            "reward": reward,
            "done": getattr(obs, "done", False),
        })

        if getattr(obs, "done", False):
            break

    return {
        "trajectory": trajectory,
        "total_reward": total_reward,
        "steps": len(trajectory),
        "done": getattr(obs, "done", False),
    }


def rollout_func_sync(
    env: Any,
    agent: AgentCallable,
    num_steps: int = 100,
    mode: str = "red",
) -> dict[str, Any]:
    """Synchronous wrapper around the async rollout function.

    For use with training loops that don't support async.
    """
    import asyncio

    return asyncio.run(rollout_func(env, agent, num_steps, mode))
