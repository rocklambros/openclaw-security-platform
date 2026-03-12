"""SQL evaluator — stateful detection using SQLite for temporal / aggregate analysis.

Stores recent events in an in-memory SQLite database and runs user-defined
SQL queries to detect patterns across multiple events (rate limiting, bursts,
session anomalies).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Any

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, EvalResult
from openclaw_security.evaluators.base import Evaluator

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    stage TEXT NOT NULL,
    session_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    user_id TEXT NOT NULL,
    tool_name TEXT,
    tool_args TEXT,
    tool_result TEXT,
    message_text TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name);
"""

MAX_EVENT_AGE_SECONDS = 3600  # purge events older than 1 hour
MAX_EVENTS = 10_000


class SQLRule:
    __slots__ = ("label", "query", "condition", "action", "reason")

    def __init__(
        self, label: str, query: str, condition: str, action: Action, reason: str
    ) -> None:
        self.label = label
        self.query = query
        self.condition = condition  # e.g. "cnt > 10"
        self.action = action
        self.reason = reason


class SQLEvaluator(Evaluator):
    eval_type = "sql"
    """Run SQL queries against a rolling window of recent events.

    Config shape::

        name: rate-limiter
        type: sql
        stages: [tool.after]
        rules:
          - label: exec-burst
            query: >
              SELECT COUNT(*) as cnt FROM events
              WHERE tool_name = 'exec' AND session_id = :session_id
              AND timestamp > :now - 60
            condition: "cnt > 10"
            action: block
            reason: Tool execution rate limit exceeded
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        super().__init__(name, config)
        self._db = sqlite3.connect(":memory:")
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._rules: list[SQLRule] = []
        for r in config.get("rules", []):
            self._rules.append(
                SQLRule(
                    label=r.get("label", "unnamed"),
                    query=r["query"],
                    condition=r["condition"],
                    action=Action(r.get("action", "block")),
                    reason=r.get("reason", ""),
                )
            )
        self._event_count = 0

    def _record_event(self, ctx: EvalContext) -> None:
        """Insert the current event into the rolling event store."""
        self._db.execute(
            """INSERT INTO events
               (timestamp, stage, session_id, channel, user_id,
                tool_name, tool_args, tool_result, message_text)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ctx.timestamp,
                ctx.stage.value,
                ctx.session_id,
                ctx.channel,
                ctx.user_id,
                ctx.tool_name,
                json.dumps(ctx.tool_args) if ctx.tool_args else None,
                str(ctx.tool_result)[:4096] if ctx.tool_result else None,
                ctx.message_text,
            ),
        )
        self._event_count += 1
        if self._event_count % 100 == 0:
            self._purge()

    def _purge(self) -> None:
        cutoff = time.time() - MAX_EVENT_AGE_SECONDS
        self._db.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        row = self._db.execute("SELECT COUNT(*) FROM events").fetchone()
        if row[0] > MAX_EVENTS:
            self._db.execute(
                "DELETE FROM events WHERE id IN "
                "(SELECT id FROM events ORDER BY timestamp ASC LIMIT ?)",
                (row[0] - MAX_EVENTS,),
            )

    def _check_condition(self, row: sqlite3.Row, condition: str) -> bool:
        """Evaluate a simple condition like 'cnt > 10' against a result row."""
        row_dict = dict(row)
        try:
            # Safe eval: only allow comparisons on numeric query results
            # Parse "field op value" conditions
            parts = condition.split()
            if len(parts) == 3:
                field, op, value = parts
                actual = float(row_dict.get(field, 0))
                expected = float(value)
                match op:
                    case ">":
                        return actual > expected
                    case ">=":
                        return actual >= expected
                    case "<":
                        return actual < expected
                    case "<=":
                        return actual <= expected
                    case "==" | "=":
                        return actual == expected
                    case "!=":
                        return actual != expected
        except (ValueError, KeyError, TypeError):
            logger.warning("Failed to evaluate SQL condition: %s", condition)
        return False

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        self._record_event(ctx)

        params = {
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            "channel": ctx.channel,
            "tool_name": ctx.tool_name or "",
            "now": time.time(),
        }

        for rule in self._rules:
            try:
                cursor = self._db.execute(rule.query, params)
                row = cursor.fetchone()
                if row and self._check_condition(row, rule.condition):
                    return self._result(
                        action=rule.action,
                        reason=rule.reason or f"SQL rule triggered: {rule.label}",
                        metadata={"rule": rule.label, "row": dict(row)},
                    )
            except Exception:
                logger.exception("SQL rule %s failed", rule.label)
                continue

        return self._result()
