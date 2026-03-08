"""LLM-powered agent using LiteLLM for model-agnostic inference.

Works with any LiteLLM-supported provider:
  - ``"anthropic/claude-sonnet-4-20250514"``
  - ``"openai/gpt-4o"``
  - ``"ollama/llama3.1:70b"``
  - ``"hosted_vllm/Qwen/Qwen3-32B"`` (pass ``api_base=`` kwarg)
"""

from __future__ import annotations

from typing import Any, Literal

from open_range.agents.parsing import extract_command
from open_range.agents.prompts import BLUE_SYSTEM_PROMPT, RED_SYSTEM_PROMPT


class LLMRangeAgent:
    """Generic agent powered by any LiteLLM model.

    Satisfies the :class:`RangeAgent` protocol.

    Args:
        model: LiteLLM model string (default ``"anthropic/claude-sonnet-4-20250514"``).
        temperature: Sampling temperature.
        max_tokens: Maximum tokens per completion.
        **litellm_kwargs: Extra kwargs forwarded to ``litellm.completion``
                          (e.g. ``api_base``, ``api_key``).
    """

    def __init__(
        self,
        model: str = "anthropic/claude-sonnet-4-20250514",
        temperature: float = 0.3,
        max_tokens: int = 512,
        **litellm_kwargs: Any,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.litellm_kwargs = litellm_kwargs
        self.messages: list[dict[str, str]] = []
        self.role: str = "red"

    def reset(self, briefing: str, role: Literal["red", "blue"]) -> None:
        """Initialize conversation history with role-specific system prompt."""
        self.role = role
        system = RED_SYSTEM_PROMPT if role == "red" else BLUE_SYSTEM_PROMPT
        self.messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": briefing},
        ]

    def act(self, observation: str) -> str:
        """Call the LLM with the conversation history and return a command.

        Appends the observation as a user message (unless it was already
        appended via ``reset``), calls litellm, extracts the shell command
        from the response, and returns it.
        """
        import litellm

        # Append observation only if it wasn't already the last user message
        if self.messages and self.messages[-1]["role"] != "user":
            self.messages.append({"role": "user", "content": observation})

        response = litellm.completion(
            model=self.model,
            messages=self.messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            **self.litellm_kwargs,
        )
        text = response.choices[0].message.content.strip()
        self.messages.append({"role": "assistant", "content": text})

        return extract_command(text)
