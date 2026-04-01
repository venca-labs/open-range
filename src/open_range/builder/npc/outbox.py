"""Async-to-sync bridge for NPC agents and the runtime.

ActionOutbox  — NPC agents (async) submit Actions; the green scheduler
               (sync) drains them into the runtime event stream.
EventInbox    — the green scheduler pushes RuntimeEvents; NPC agents
               poll for observations.
SimClock      — shared simulated-time reference updated by the runtime,
               read by NPC agents.
"""

from __future__ import annotations

import asyncio
import threading
from collections import deque

from open_range.runtime_types import Action, RuntimeEvent


class ActionOutbox:
    """Thread-safe queue: NPC agents submit, scheduler drains."""

    def __init__(self, max_size: int = 200) -> None:
        self._queue: deque[Action] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def submit(self, action: Action) -> None:
        """Called by async NPC agents (from asyncio tasks)."""
        with self._lock:
            self._queue.append(action)

    def drain(self) -> tuple[Action, ...]:
        """Called by the green scheduler (from the sync runtime loop)."""
        with self._lock:
            actions = tuple(self._queue)
            self._queue.clear()
            return actions

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)


class EventInbox:
    """Per-NPC event feed from the runtime.

    push() is called synchronously by the scheduler.
    poll() is called by async NPC agent tasks.
    """

    def __init__(self, max_size: int = 200) -> None:
        self._events: deque[RuntimeEvent] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def push(self, event: RuntimeEvent) -> None:
        """Called synchronously by the scheduler's record_event()."""
        with self._lock:
            self._events.append(event)

    def poll(self) -> tuple[RuntimeEvent, ...]:
        """Called by async NPC agents — returns and clears pending events."""
        with self._lock:
            events = tuple(self._events)
            self._events.clear()
            return events

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


class SimClock:
    """Shared simulated-time clock.

    Updated by the runtime via advance(); read by NPC agents via now.
    Thread-safe for concurrent reads from multiple agent tasks.
    """

    def __init__(self) -> None:
        self._time: float = 0.0
        self._lock = threading.Lock()

    @property
    def now(self) -> float:
        with self._lock:
            return self._time

    def advance(self, t: float) -> None:
        with self._lock:
            self._time = t

    def reset(self) -> None:
        with self._lock:
            self._time = 0.0


class MessageStore:
    """Shared message store for all async communication modalities.

    Thread-safe.  Senders deposit messages (email, chat, etc.) and
    recipients pick them up.  Each message carries a ``modality`` field
    so the recipient knows how it arrived and can reply on the same
    medium.

    Designed for future expansion: when synchronous modalities (voice,
    video) are added, they would use a separate signaling mechanism
    (e.g., a ``CallStore``) since they require both parties to be
    available simultaneously.
    """

    def __init__(self) -> None:
        self._inbox: dict[str, list[dict[str, str]]] = {}
        self._lock = threading.Lock()

    def deliver(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        modality: str = "email",
    ) -> None:
        """Sender deposits a message for the recipient."""
        with self._lock:
            self._inbox.setdefault(recipient, []).append({
                "sender": sender,
                "subject": subject,
                "body": body,
                "modality": modality,
            })

    def pickup(
        self,
        recipient: str,
        sender: str | None = None,
        modality: str | None = None,
    ) -> dict[str, str] | None:
        """Recipient picks up the next message, optionally filtered."""
        with self._lock:
            queue = self._inbox.get(recipient, [])
            for i, msg in enumerate(queue):
                if sender and msg["sender"] != sender:
                    continue
                if modality and msg.get("modality") != modality:
                    continue
                return queue.pop(i)
            return None

    def pending_count(self, recipient: str, modality: str | None = None) -> int:
        with self._lock:
            queue = self._inbox.get(recipient, [])
            if modality:
                return sum(1 for m in queue if m.get("modality") == modality)
            return len(queue)

    def reset(self) -> None:
        with self._lock:
            self._inbox.clear()


# Backward-compatible alias
MailStore = MessageStore
