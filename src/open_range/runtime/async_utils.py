"""Helpers for running async backend calls from sync code."""

from __future__ import annotations

import asyncio
from concurrent.futures import Future
from threading import Thread
from typing import TypeVar

T = TypeVar("T")


def run_async(awaitable) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    result: Future[T] = Future()

    def _runner() -> None:
        try:
            result.set_result(asyncio.run(awaitable))
        except Exception as exc:  # noqa: BLE001
            result.set_exception(exc)

    thread = Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()
    return result.result()
