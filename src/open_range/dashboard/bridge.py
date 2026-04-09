"""Thread-safe event bridge connecting the runtime to SSE clients."""

from __future__ import annotations

import asyncio
import threading
from collections import deque
from typing import AsyncGenerator

from open_range.runtime_types import RuntimeEvent


class EventBridge:
    """Fan-out bridge: runtime pushes events, SSE clients subscribe.

    The bridge keeps a rolling buffer of the last *max_buffer* events so that
    late-joining clients receive recent history before the live tail.
    """

    def __init__(self, *, max_buffer: int = 200) -> None:
        self._buffer: deque[RuntimeEvent] = deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        self._subscribers: list[asyncio.Queue[RuntimeEvent | None]] = []

    def push(self, event: RuntimeEvent) -> None:
        """Called from the runtime thread to broadcast an event."""
        with self._lock:
            self._buffer.append(event)
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass  # slow consumer, drop oldest

    def snapshot_buffer(self) -> list[RuntimeEvent]:
        """Return a copy of the current rolling buffer."""
        with self._lock:
            return list(self._buffer)

    async def subscribe(self) -> AsyncGenerator[RuntimeEvent, None]:
        """Async generator that yields events as they arrive.

        First replays buffered events, then streams live.
        """
        q: asyncio.Queue[RuntimeEvent | None] = asyncio.Queue(maxsize=500)
        with self._lock:
            backlog = list(self._buffer)
            self._subscribers.append(q)
        try:
            for event in backlog:
                yield event
            while True:
                event = await q.get()
                if event is None:
                    break
                yield event
        finally:
            with self._lock:
                self._subscribers.remove(q)

    def close(self) -> None:
        """Signal all subscribers to stop."""
        with self._lock:
            for q in self._subscribers:
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
