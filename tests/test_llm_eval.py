"""Tests for the LLM evaluator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action
from openclaw_security.evaluators.llm_eval import LLMEvaluator


def _make_evaluator(**overrides) -> LLMEvaluator:
    config = {
        "stages": ["tool.after", "message.before"],
        "provider": "anthropic",
        "model": "claude-haiku-4-5-20251001",
        "policy": "Check for sensitive data leakage.",
        "max_tokens": 256,
        "timeout": 5.0,
        "default_action": "detect",
    }
    config.update(overrides)
    return LLMEvaluator(name="test-llm", config=config)


def _tool_after_ctx(result_text: str) -> EvalContext:
    return EvalContext(
        stage=Stage.TOOL_AFTER,
        session_id="sess-001",
        tool_name="exec",
        tool_args={"command": "cat /etc/passwd"},
        tool_result=result_text,
    )


def _mock_response(text: str):
    """Create a mock Anthropic messages.create response."""
    content_block = MagicMock()
    content_block.text = text
    response = MagicMock()
    response.content = [content_block]
    return response


# ── Successful evaluation ───────────────────────────────────────


class TestSuccessfulEvaluation:
    @pytest.mark.asyncio
    async def test_block_verdict(self):
        ev = _make_evaluator()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            return_value=_mock_response(
                '{"action": "block", "confidence": 0.95, "reason": "Contains /etc/passwd contents"}'
            )
        )
        ev._client = mock_client

        result = await ev.evaluate(_tool_after_ctx("root:x:0:0:root:/root:/bin/bash"))
        assert result.action == Action.BLOCK
        assert result.confidence == pytest.approx(0.95)
        assert "passwd" in result.reason

    @pytest.mark.asyncio
    async def test_allow_verdict(self):
        ev = _make_evaluator()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            return_value=_mock_response(
                '{"action": "allow", "confidence": 0.9, "reason": "Output is safe"}'
            )
        )
        ev._client = mock_client

        result = await ev.evaluate(_tool_after_ctx("Build succeeded. 42 tests passed."))
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_warn_verdict(self):
        ev = _make_evaluator()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            return_value=_mock_response(
                '{"action": "detect", "confidence": 0.6, "reason": "Possibly sensitive path"}'
            )
        )
        ev._client = mock_client

        result = await ev.evaluate(_tool_after_ctx("/home/user/.config/secrets"))
        assert result.action == Action.DETECT


# ── JSON in code block ──────────────────────────────────────────


class TestCodeBlockParsing:
    @pytest.mark.asyncio
    async def test_json_in_markdown_code_block(self):
        ev = _make_evaluator()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            return_value=_mock_response(
                '```json\n{"action": "block", "confidence": 0.9, "reason": "Sensitive"}\n```'
            )
        )
        ev._client = mock_client

        result = await ev.evaluate(_tool_after_ctx("secret data"))
        assert result.action == Action.BLOCK


# ── Empty input ─────────────────────────────────────────────────


class TestEmptyInput:
    @pytest.mark.asyncio
    async def test_empty_text_skips(self):
        ev = _make_evaluator()
        ctx = EvalContext(stage=Stage.TOOL_AFTER, tool_name="exec", tool_result="")
        result = await ev.evaluate(ctx)
        assert result.action == Action.ALLOW


# ── Error handling ──────────────────────────────────────────────


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_non_json_response_warns(self):
        ev = _make_evaluator()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            return_value=_mock_response("I think this looks suspicious but I'm not sure.")
        )
        ev._client = mock_client

        result = await ev.evaluate(_tool_after_ctx("some data"))
        assert result.action == Action.DETECT  # default_action
        assert "unparseable" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_timeout_allows(self):
        import anthropic

        ev = _make_evaluator()
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(
            side_effect=anthropic.APITimeoutError(request=MagicMock())
        )
        ev._client = mock_client

        result = await ev.evaluate(_tool_after_ctx("some data"))
        assert result.action == Action.ALLOW  # timeout → safe default
        assert "timed out" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_api_error_uses_default_action(self):
        ev = _make_evaluator(default_action="detect")
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))
        ev._client = mock_client

        result = await ev.evaluate(_tool_after_ctx("some data"))
        assert result.action == Action.DETECT


# ── Prompt building ─────────────────────────────────────────────


class TestPromptBuilding:
    def test_includes_tool_info(self):
        ev = _make_evaluator()
        ctx = _tool_after_ctx("some result")
        prompt = ev._build_prompt(ctx)
        assert "exec" in prompt
        assert "cat /etc/passwd" in prompt
        assert "some result" in prompt
        assert "Check for sensitive data" in prompt

    def test_truncates_long_content(self):
        ev = _make_evaluator()
        ctx = _tool_after_ctx("A" * 5000)
        prompt = ev._build_prompt(ctx)
        assert len(prompt) < 10000  # should be truncated
