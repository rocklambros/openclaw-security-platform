"""Tests for the Regex evaluator."""

import pytest

from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action
from openclaw_security.evaluators.regex_eval import RegexEvaluator


def _make_evaluator(rules: list[dict]) -> RegexEvaluator:
    return RegexEvaluator(
        name="test-regex",
        config={"stages": ["tool.before", "tool.after"], "rules": rules},
    )


# ── True positives ──────────────────────────────────────────────


class TestSecretDetection:
    @pytest.mark.asyncio
    async def test_aws_access_key(self, tool_after_ctx: EvalContext):
        tool_after_ctx.tool_result = "Found key: AKIAIOSFODNN7EXAMPLE"
        ev = _make_evaluator(
            [{"label": "AWS Key", "pattern": "AKIA[0-9A-Z]{16}", "action": "redact"}]
        )
        result = await ev.evaluate(tool_after_ctx)
        assert result.action == Action.REDACT
        assert "AWS Key" in result.reason
        assert "AKIAIOSFODNN7EXAMPLE" not in (result.redacted or "")
        assert "[REDACTED]" in (result.redacted or "")

    @pytest.mark.asyncio
    async def test_github_token(self, tool_after_ctx: EvalContext):
        tool_after_ctx.tool_result = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        ev = _make_evaluator(
            [{"label": "GitHub PAT", "pattern": "ghp_[A-Za-z0-9]{36}", "action": "redact"}]
        )
        result = await ev.evaluate(tool_after_ctx)
        assert result.action == Action.REDACT

    @pytest.mark.asyncio
    async def test_private_key_block(self, tool_after_ctx: EvalContext):
        tool_after_ctx.tool_result = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        ev = _make_evaluator(
            [
                {
                    "label": "Private Key",
                    "pattern": "-----BEGIN (RSA |EC )?PRIVATE KEY-----",
                    "action": "block",
                }
            ]
        )
        result = await ev.evaluate(tool_after_ctx)
        assert result.action == Action.BLOCK


class TestDangerousCommands:
    @pytest.mark.asyncio
    async def test_rm_rf_root(self, tool_before_ctx: EvalContext):
        tool_before_ctx.tool_args = {"command": "rm -rf /"}
        ev = _make_evaluator(
            [
                {
                    "label": "rm -rf /",
                    "pattern": r"rm\s+-rf\s+/",
                    "action": "block",
                    "fields": ["tool_args.command"],
                }
            ]
        )
        result = await ev.evaluate(tool_before_ctx)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_drop_table(self, tool_before_ctx: EvalContext):
        tool_before_ctx.tool_args = {"command": "psql -c 'DROP TABLE users;'"}
        ev = _make_evaluator(
            [{"label": "DROP TABLE", "pattern": r"(?i)DROP\s+TABLE", "action": "block"}]
        )
        result = await ev.evaluate(tool_before_ctx)
        assert result.action == Action.BLOCK


class TestPII:
    @pytest.mark.asyncio
    async def test_ssn(self, tool_after_ctx: EvalContext):
        tool_after_ctx.tool_result = "SSN: 123-45-6789"
        ev = _make_evaluator(
            [{"label": "SSN", "pattern": r"\b\d{3}-\d{2}-\d{4}\b", "action": "redact"}]
        )
        result = await ev.evaluate(tool_after_ctx)
        assert result.action == Action.REDACT
        assert "123-45-6789" not in (result.redacted or "")

    @pytest.mark.asyncio
    async def test_credit_card(self, tool_after_ctx: EvalContext):
        tool_after_ctx.tool_result = "Card: 4111111111111111"
        ev = _make_evaluator(
            [
                {
                    "label": "Visa",
                    "pattern": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
                    "action": "redact",
                }
            ]
        )
        result = await ev.evaluate(tool_after_ctx)
        assert result.action == Action.REDACT


# ── True negatives ──────────────────────────────────────────────


class TestSafeInputs:
    @pytest.mark.asyncio
    async def test_normal_command(self, tool_before_ctx: EvalContext):
        tool_before_ctx.tool_args = {"command": "ls -la /home/user"}
        ev = _make_evaluator(
            [{"label": "rm -rf /", "pattern": r"rm\s+-rf\s+/", "action": "block"}]
        )
        result = await ev.evaluate(tool_before_ctx)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_safe_text(self, tool_after_ctx: EvalContext):
        tool_after_ctx.tool_result = "Build completed successfully. 42 tests passed."
        ev = _make_evaluator(
            [
                {"label": "AWS Key", "pattern": "AKIA[0-9A-Z]{16}", "action": "redact"},
                {"label": "SSN", "pattern": r"\b\d{3}-\d{2}-\d{4}\b", "action": "redact"},
            ]
        )
        result = await ev.evaluate(tool_after_ctx)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_empty_text(self, tool_before_ctx: EvalContext):
        tool_before_ctx.tool_args = {}
        ev = _make_evaluator(
            [{"label": "anything", "pattern": ".*secret.*", "action": "block"}]
        )
        result = await ev.evaluate(tool_before_ctx)
        assert result.action == Action.ALLOW


# ── Field targeting ─────────────────────────────────────────────


class TestFieldTargeting:
    @pytest.mark.asyncio
    async def test_field_match_only_scans_specified_field(self, tool_before_ctx: EvalContext):
        """Pattern targets tool_args.command but the match is in tool_result — should allow."""
        tool_before_ctx.tool_args = {"command": "echo hello"}
        tool_before_ctx.tool_result = "rm -rf /"
        ev = _make_evaluator(
            [
                {
                    "label": "rm -rf",
                    "pattern": r"rm\s+-rf\s+/",
                    "action": "block",
                    "fields": ["tool_args.command"],
                }
            ]
        )
        result = await ev.evaluate(tool_before_ctx)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_no_fields_scans_all_text(self, tool_before_ctx: EvalContext):
        """Without fields specified, scan all searchable text."""
        tool_before_ctx.tool_args = {"command": "echo hello", "note": "secret_key=ABCD1234EFGH5678"}
        ev = _make_evaluator(
            [{"label": "secret", "pattern": r"secret_key=\w+", "action": "warn"}]
        )
        result = await ev.evaluate(tool_before_ctx)
        assert result.action == Action.WARN
