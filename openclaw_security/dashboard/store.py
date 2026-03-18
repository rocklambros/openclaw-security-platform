"""In-memory event store for the dashboard — ring buffer with stats."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DashboardEvent:
    """A single evaluation event stored for the dashboard."""

    id: int
    timestamp: float
    stage: str
    session_id: str
    user_id: str
    tool_name: str | None
    action: str
    blocked: bool
    reasons: list[str]
    redacted: bool
    evaluator_results: list[dict[str, Any]]
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "stage": self.stage,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "tool_name": self.tool_name,
            "action": self.action,
            "blocked": self.blocked,
            "reasons": self.reasons,
            "redacted": self.redacted,
            "evaluator_results": self.evaluator_results,
            "elapsed_ms": self.elapsed_ms,
        }


class EventStore:
    """Thread-safe in-memory ring buffer for dashboard events."""

    def __init__(self, max_events: int = 10_000) -> None:
        self._events: deque[DashboardEvent] = deque(maxlen=max_events)
        self._counter = 0
        self._subscribers: list[asyncio.Queue[DashboardEvent]] = []

        # Running stats
        self.total_count = 0
        self.action_counts: dict[str, int] = {"allow": 0, "block": 0, "warn": 0, "redact": 0}
        self.stage_counts: dict[str, int] = {}

    def push(self, event: DashboardEvent) -> None:
        """Add an event and notify all SSE subscribers."""
        self._counter += 1
        event.id = self._counter
        self._events.append(event)

        self.total_count += 1
        self.action_counts[event.action] = self.action_counts.get(event.action, 0) + 1
        self.stage_counts[event.stage] = self.stage_counts.get(event.stage, 0) + 1

        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # slow consumer, drop event

    def history(
        self,
        limit: int = 50,
        offset: int = 0,
        action: str | None = None,
        stage: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return recent events with optional filters."""
        events = list(self._events)
        events.reverse()  # newest first

        if action:
            events = [e for e in events if e.action == action]
        if stage:
            events = [e for e in events if e.stage == stage]

        return [e.to_dict() for e in events[offset : offset + limit]]

    def stats(self) -> dict[str, Any]:
        """Return aggregate statistics."""
        return {
            "total": self.total_count,
            "actions": dict(self.action_counts),
            "stages": dict(self.stage_counts),
        }

    def subscribe(self) -> asyncio.Queue[DashboardEvent]:
        """Create a new SSE subscriber queue."""
        q: asyncio.Queue[DashboardEvent] = asyncio.Queue(maxsize=256)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[DashboardEvent]) -> None:
        """Remove a subscriber queue."""
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass
