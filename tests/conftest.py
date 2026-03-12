"""Shared fixtures for the test suite."""

from __future__ import annotations

import pytest

from openclaw_security.engine.context import EvalContext, Stage


@pytest.fixture
def tool_before_ctx() -> EvalContext:
    """A typical tool.before context for an exec tool call."""
    return EvalContext(
        stage=Stage.TOOL_BEFORE,
        session_id="sess-001",
        channel="whatsapp",
        user_id="user-42",
        tool_name="exec",
        tool_args={"command": "ls -la /home/user"},
    )


@pytest.fixture
def tool_after_ctx() -> EvalContext:
    """A typical tool.after context with a tool result."""
    return EvalContext(
        stage=Stage.TOOL_AFTER,
        session_id="sess-001",
        channel="whatsapp",
        user_id="user-42",
        tool_name="exec",
        tool_args={"command": "cat config.json"},
        tool_result='{"db_host": "localhost", "db_pass": "s3cret"}',
    )


@pytest.fixture
def message_before_ctx() -> EvalContext:
    """A typical message.before context."""
    return EvalContext(
        stage=Stage.MESSAGE_BEFORE,
        session_id="sess-001",
        channel="slack",
        user_id="user-42",
        message_text="Please summarize yesterday's sales report",
    )
