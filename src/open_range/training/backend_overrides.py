"""Shared transport for optional backend override settings."""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BackendOverrides:
    """Optional backend settings threaded through CLI-driven subprocess flows."""

    model: str | None = None
    base_url: str | None = None
    asr_url: str | None = None
    tts_url: str | None = None

    def as_env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        if self.model:
            env["OPENRANGE_MODEL_ID"] = self.model
        if self.base_url:
            env["OPENRANGE_BASE_URL"] = self.base_url
        if self.asr_url:
            env["OPENRANGE_ASR_URL"] = self.asr_url
        if self.tts_url:
            env["OPENRANGE_TTS_URL"] = self.tts_url
        return env

    def apply(self, env: MutableMapping[str, str]) -> dict[str, str]:
        applied = self.as_env()
        env.update(applied)
        return applied

    def append_grpo_args(self, command: list[str]) -> None:
        if self.model:
            command.extend(["--backend-model", self.model])
        if self.base_url:
            command.extend(["--base-url", self.base_url])
        if self.asr_url:
            command.extend(["--asr-url", self.asr_url])
        if self.tts_url:
            command.extend(["--tts-url", self.tts_url])
