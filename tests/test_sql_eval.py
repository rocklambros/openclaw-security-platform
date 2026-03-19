"""Tests for the SQL evaluator."""

import time

import pytest

from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action
from openclaw_security.evaluators.sql_eval import SQLEvaluator


def _make_evaluator(rules: list[dict]) -> SQLEvaluator:
    return SQLEvaluator(
        name="test-sql",
        config={"stages": ["tool.before", "tool.after"], "rules": rules},
    )


def _exec_ctx(session_id: str = "sess-001") -> EvalContext:
    return EvalContext(
        stage=Stage.TOOL_BEFORE,
        session_id=session_id,
        tool_name="exec",
        tool_args={"command": "echo hello"},
    )


# ── Rate limiting ───────────────────────────────────────────────


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_under_threshold_allows(self):
        ev = _make_evaluator(
            [
                {
                    "label": "exec-burst",
                    "query": (
                        "SELECT COUNT(*) as cnt FROM events "
                        "WHERE tool_name = 'exec' AND session_id = :session_id "
                        "AND timestamp > :now - 60"
                    ),
                    "condition": "cnt > 5",
                    "action": "block",
                    "reason": "Rate limit exceeded",
                }
            ]
        )
        # Send 3 events — under the threshold of 5
        for _ in range(3):
            result = await ev.evaluate(_exec_ctx())

        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_over_threshold_blocks(self):
        ev = _make_evaluator(
            [
                {
                    "label": "exec-burst",
                    "query": (
                        "SELECT COUNT(*) as cnt FROM events "
                        "WHERE tool_name = 'exec' AND session_id = :session_id "
                        "AND timestamp > :now - 60"
                    ),
                    "condition": "cnt > 5",
                    "action": "block",
                    "reason": "Rate limit exceeded",
                }
            ]
        )
        # Send 6 events — over the threshold of 5
        for i in range(6):
            result = await ev.evaluate(_exec_ctx())

        assert result.action == Action.BLOCK
        assert "Rate limit" in result.reason

    @pytest.mark.asyncio
    async def test_different_sessions_isolated(self):
        ev = _make_evaluator(
            [
                {
                    "label": "exec-burst",
                    "query": (
                        "SELECT COUNT(*) as cnt FROM events "
                        "WHERE tool_name = 'exec' AND session_id = :session_id "
                        "AND timestamp > :now - 60"
                    ),
                    "condition": "cnt > 5",
                    "action": "block",
                }
            ]
        )
        # Send 10 events for session A
        for _ in range(10):
            await ev.evaluate(_exec_ctx("session-A"))

        # Session B should still be under threshold
        result = await ev.evaluate(_exec_ctx("session-B"))
        assert result.action == Action.ALLOW


# ── Different tools ─────────────────────────────────────────────


class TestToolFiltering:
    @pytest.mark.asyncio
    async def test_only_counts_matching_tool(self):
        ev = _make_evaluator(
            [
                {
                    "label": "write-burst",
                    "query": (
                        "SELECT COUNT(*) as cnt FROM events "
                        "WHERE tool_name = 'write_file' AND session_id = :session_id "
                        "AND timestamp > :now - 60"
                    ),
                    "condition": "cnt > 3",
                    "action": "block",
                }
            ]
        )
        # Send 10 exec events — shouldn't trigger write_file rule
        for _ in range(10):
            result = await ev.evaluate(_exec_ctx())

        assert result.action == Action.ALLOW


# ── Event recording ─────────────────────────────────────────────


class TestEventRecording:
    @pytest.mark.asyncio
    async def test_events_are_persisted(self):
        ev = _make_evaluator(
            [
                {
                    "label": "count-all",
                    "query": "SELECT COUNT(*) as cnt FROM events",
                    "condition": "cnt > 0",
                    "action": "detect",
                }
            ]
        )
        # First event — after recording, count will be 1
        result = await ev.evaluate(_exec_ctx())
        assert result.action == Action.DETECT

    @pytest.mark.asyncio
    async def test_records_message_events(self):
        ev = _make_evaluator(
            [
                {
                    "label": "count-messages",
                    "query": (
                        "SELECT COUNT(*) as cnt FROM events "
                        "WHERE message_text IS NOT NULL"
                    ),
                    "condition": "cnt > 0",
                    "action": "detect",
                }
            ]
        )
        ctx = EvalContext(
            stage=Stage.TOOL_AFTER,  # using tool.after since that's in our stages
            session_id="sess-001",
            message_text="Hello world",
        )
        result = await ev.evaluate(ctx)
        assert result.action == Action.DETECT


# ── Condition operators ─────────────────────────────────────────


class TestConditionOperators:
    @pytest.mark.asyncio
    async def test_less_than(self):
        ev = _make_evaluator(
            [
                {
                    "label": "few-events",
                    "query": "SELECT COUNT(*) as cnt FROM events",
                    "condition": "cnt < 10",
                    "action": "detect",
                }
            ]
        )
        result = await ev.evaluate(_exec_ctx())
        assert result.action == Action.DETECT  # 1 < 10

    @pytest.mark.asyncio
    async def test_equals(self):
        ev = _make_evaluator(
            [
                {
                    "label": "exactly-one",
                    "query": "SELECT COUNT(*) as cnt FROM events",
                    "condition": "cnt == 1",
                    "action": "detect",
                }
            ]
        )
        result = await ev.evaluate(_exec_ctx())
        assert result.action == Action.DETECT  # exactly 1 event
