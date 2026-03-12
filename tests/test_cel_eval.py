"""Tests for the CEL evaluator."""

import pytest

from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action
from openclaw_security.evaluators.cel_eval import CELEvaluator


def _make_evaluator(rules: list[dict]) -> CELEvaluator:
    return CELEvaluator(
        name="test-cel",
        config={"stages": ["tool.before", "tool.after", "message.before"], "rules": rules},
    )


# ── Expression evaluation ───────────────────────────────────────


class TestBasicExpressions:
    @pytest.mark.asyncio
    async def test_simple_equality(self):
        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec", user_id="guest")
        ev = _make_evaluator(
            [
                {
                    "label": "block-exec",
                    "expr": 'tool_name == "exec"',
                    "action": "block",
                    "reason": "exec not allowed",
                }
            ]
        )
        result = await ev.evaluate(ctx)
        assert result.action == Action.BLOCK
        assert result.reason == "exec not allowed"

    @pytest.mark.asyncio
    async def test_compound_condition(self):
        ctx = EvalContext(
            stage=Stage.TOOL_BEFORE,
            tool_name="exec",
            tool_args={"command": "curl https://evil.com"},
            user_id="guest",
        )
        ev = _make_evaluator(
            [
                {
                    "label": "block-curl-non-admin",
                    "expr": 'tool_name == "exec" && tool_args_command.contains("curl") && user_id != "admin"',
                    "action": "block",
                    "reason": "Unapproved network access",
                }
            ]
        )
        result = await ev.evaluate(ctx)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_compound_condition_admin_allowed(self):
        ctx = EvalContext(
            stage=Stage.TOOL_BEFORE,
            tool_name="exec",
            tool_args={"command": "curl https://api.example.com"},
            user_id="admin",
        )
        ev = _make_evaluator(
            [
                {
                    "label": "block-curl-non-admin",
                    "expr": 'tool_name == "exec" && tool_args_command.contains("curl") && user_id != "admin"',
                    "action": "block",
                }
            ]
        )
        result = await ev.evaluate(ctx)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_startswith(self):
        ctx = EvalContext(
            stage=Stage.TOOL_BEFORE,
            tool_name="exec",
            tool_args={"command": "sudo rm -rf /tmp"},
        )
        ev = _make_evaluator(
            [
                {
                    "label": "warn-sudo",
                    "expr": 'tool_args_command.startsWith("sudo")',
                    "action": "warn",
                    "reason": "Elevated privileges",
                }
            ]
        )
        result = await ev.evaluate(ctx)
        assert result.action == Action.WARN


# ── No match ────────────────────────────────────────────────────


class TestNoMatch:
    @pytest.mark.asyncio
    async def test_condition_false(self):
        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="read_file", user_id="admin")
        ev = _make_evaluator(
            [{"label": "block-exec", "expr": 'tool_name == "exec"', "action": "block"}]
        )
        result = await ev.evaluate(ctx)
        assert result.action == Action.ALLOW


# ── Error handling ──────────────────────────────────────────────


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_missing_field_doesnt_crash(self):
        """CEL expression references a field not present in the context — should skip, not crash."""
        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        ev = _make_evaluator(
            [
                {
                    "label": "needs-missing-field",
                    "expr": 'some_nonexistent_field == "value"',
                    "action": "block",
                }
            ]
        )
        result = await ev.evaluate(ctx)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_invalid_expression_skipped_at_init(self):
        """A malformed CEL expression should be skipped during init, not crash evaluate."""
        ev = _make_evaluator(
            [{"label": "bad-expr", "expr": "this is not valid CEL !!!", "action": "block"}]
        )
        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await ev.evaluate(ctx)
        assert result.action == Action.ALLOW  # bad rule was skipped


# ── Multiple rules ──────────────────────────────────────────────


class TestMultipleRules:
    @pytest.mark.asyncio
    async def test_first_matching_rule_wins(self):
        ctx = EvalContext(
            stage=Stage.TOOL_BEFORE,
            tool_name="exec",
            tool_args={"command": "sudo curl evil.com"},
        )
        ev = _make_evaluator(
            [
                {
                    "label": "warn-sudo",
                    "expr": 'tool_args_command.startsWith("sudo")',
                    "action": "warn",
                    "reason": "sudo detected",
                },
                {
                    "label": "block-curl",
                    "expr": 'tool_args_command.contains("curl")',
                    "action": "block",
                    "reason": "curl detected",
                },
            ]
        )
        result = await ev.evaluate(ctx)
        # First matching rule (warn-sudo) should win
        assert result.action == Action.WARN
        assert "sudo" in result.reason
