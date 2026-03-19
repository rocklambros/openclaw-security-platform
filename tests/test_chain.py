"""Tests for the evaluation chain — ordering, short-circuit, aggregation, error handling."""

from __future__ import annotations

import pytest

from openclaw_security.engine.chain import EvaluatorChain
from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action, EvalResult, aggregate
from openclaw_security.evaluators.base import Evaluator


# ── Test helpers ────────────────────────────────────────────────


class StubEvaluator(Evaluator):
    """Evaluator that returns a preconfigured result."""

    def __init__(self, name: str, action: Action = Action.ALLOW, type_hint: str = "regex"):
        super().__init__(name, {"stages": ["tool.before", "tool.after", "message.before"]})
        self.eval_type = type_hint
        self._action = action
        self.call_count = 0

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        self.call_count += 1
        return self._result(action=self._action, reason=f"{self.name} fired")


class FailingEvaluator(Evaluator):
    """Evaluator that always raises."""

    def __init__(self, name: str):
        super().__init__(name, {"stages": ["tool.before", "tool.after"]})

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        raise RuntimeError("Evaluator crashed")


class StageLimitedEvaluator(Evaluator):
    """Evaluator that only runs on specific stages."""

    def __init__(self, name: str, stages: list[str], action: Action = Action.BLOCK):
        super().__init__(name, {"stages": stages})
        self._action = action
        self.call_count = 0

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        self.call_count += 1
        return self._result(action=self._action, reason=f"{self.name} fired")


# ── Cost ordering ───────────────────────────────────────────────


class TestCostOrdering:
    def test_regex_before_sigma_before_llm(self):
        chain = EvaluatorChain()
        llm = StubEvaluator("llm-guard", type_hint="llm")
        regex = StubEvaluator("regex-guard", type_hint="regex")
        sigma = StubEvaluator("sigma-guard", type_hint="sigma")

        # Add in wrong order
        chain.add(llm)
        chain.add(sigma)
        chain.add(regex)

        names = [e.name for e in chain._evaluators]
        assert names.index("regex-guard") < names.index("sigma-guard")
        assert names.index("sigma-guard") < names.index("llm-guard")


# ── Short-circuit ───────────────────────────────────────────────


class TestShortCircuit:
    @pytest.mark.asyncio
    async def test_block_stops_chain(self):
        blocker = StubEvaluator("blocker", Action.BLOCK)
        after = StubEvaluator("after-blocker", Action.ALLOW)
        chain = EvaluatorChain([blocker, after])

        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)

        assert result.action == Action.BLOCK
        assert blocker.call_count == 1
        assert after.call_count == 0  # never called

    @pytest.mark.asyncio
    async def test_warn_does_not_stop_chain(self):
        warner = StubEvaluator("warner", Action.DETECT)
        after = StubEvaluator("after-warner", Action.ALLOW)
        chain = EvaluatorChain([warner, after])

        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)

        assert warner.call_count == 1
        assert after.call_count == 1
        # Warn is highest action
        assert result.action == Action.DETECT

    @pytest.mark.asyncio
    async def test_allow_runs_all(self):
        e1 = StubEvaluator("e1", Action.ALLOW)
        e2 = StubEvaluator("e2", Action.ALLOW)
        e3 = StubEvaluator("e3", Action.ALLOW)
        chain = EvaluatorChain([e1, e2, e3])

        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)

        assert result.action == Action.ALLOW
        assert e1.call_count == 1
        assert e2.call_count == 1
        assert e3.call_count == 1


# ── Stage filtering ─────────────────────────────────────────────


class TestStageFiltering:
    @pytest.mark.asyncio
    async def test_tool_before_evaluator_skips_message_events(self):
        ev = StageLimitedEvaluator("tool-only", stages=["tool.before"], action=Action.BLOCK)
        chain = EvaluatorChain([ev])

        ctx = EvalContext(stage=Stage.MESSAGE_BEFORE, message_text="Hello")
        result = await chain.run(ctx)

        assert result.action == Action.ALLOW
        assert ev.call_count == 0

    @pytest.mark.asyncio
    async def test_message_evaluator_runs_on_message(self):
        ev = StageLimitedEvaluator("msg-only", stages=["message.before"], action=Action.DETECT)
        chain = EvaluatorChain([ev])

        ctx = EvalContext(stage=Stage.MESSAGE_BEFORE, message_text="Hello")
        result = await chain.run(ctx)

        assert result.action == Action.DETECT
        assert ev.call_count == 1

    @pytest.mark.asyncio
    async def test_mixed_stages(self):
        msg_ev = StageLimitedEvaluator("msg-blocker", stages=["message.before"], action=Action.BLOCK)
        tool_ev = StageLimitedEvaluator("tool-blocker", stages=["tool.before"], action=Action.BLOCK)
        chain = EvaluatorChain([msg_ev, tool_ev])

        # Tool event — only tool_ev should run
        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)

        assert result.action == Action.BLOCK
        assert msg_ev.call_count == 0
        assert tool_ev.call_count == 1


# ── Error handling ──────────────────────────────────────────────


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_failing_evaluator_demoted_to_warn(self):
        failing = FailingEvaluator("crasher")
        chain = EvaluatorChain([failing])

        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)

        assert result.action == Action.DETECT
        assert len(result.results) == 1
        assert "error" in result.results[0].reason.lower()
        assert result.results[0].confidence == 0.0

    @pytest.mark.asyncio
    async def test_chain_continues_after_error(self):
        failing = FailingEvaluator("crasher")
        after = StubEvaluator("after-crash", Action.ALLOW)
        chain = EvaluatorChain([failing, after])

        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)

        # Failing evaluator warns, chain continues
        assert after.call_count == 1
        assert result.action == Action.DETECT  # warn from the crash


# ── Empty chain ─────────────────────────────────────────────────


class TestEmptyChain:
    @pytest.mark.asyncio
    async def test_no_evaluators_allows(self):
        chain = EvaluatorChain()
        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)
        assert result.action == Action.ALLOW
        assert len(result.results) == 0


# ── Aggregation ─────────────────────────────────────────────────


class TestAggregation:
    def test_block_wins_over_warn(self):
        results = [
            EvalResult(evaluator="a", action=Action.DETECT, reason="a warns"),
            EvalResult(evaluator="b", action=Action.BLOCK, reason="b blocks"),
        ]
        agg = aggregate(results)
        assert agg.action == Action.BLOCK
        assert agg.blocked

    def test_redact_wins_over_warn(self):
        results = [
            EvalResult(evaluator="a", action=Action.DETECT, reason="a warns"),
            EvalResult(evaluator="b", action=Action.REDACT, redacted="[SAFE]"),
        ]
        agg = aggregate(results)
        assert agg.action == Action.REDACT
        assert agg.redacted == "[SAFE]"

    def test_block_wins_over_redact(self):
        results = [
            EvalResult(evaluator="a", action=Action.REDACT, redacted="[SAFE]"),
            EvalResult(evaluator="b", action=Action.BLOCK, reason="blocked"),
        ]
        agg = aggregate(results)
        assert agg.action == Action.BLOCK

    def test_all_allow(self):
        results = [
            EvalResult(evaluator="a", action=Action.ALLOW),
            EvalResult(evaluator="b", action=Action.ALLOW),
        ]
        agg = aggregate(results)
        assert agg.action == Action.ALLOW
        assert not agg.blocked

    def test_empty_results(self):
        agg = aggregate([])
        assert agg.action == Action.ALLOW

    def test_reasons_only_from_non_allow(self):
        results = [
            EvalResult(evaluator="a", action=Action.ALLOW, reason="all good"),
            EvalResult(evaluator="b", action=Action.DETECT, reason="suspicious"),
        ]
        agg = aggregate(results)
        assert "suspicious" in agg.reasons
        assert "all good" not in agg.reasons


# ── Timing metadata ─────────────────────────────────────────────


class TestTimingMetadata:
    @pytest.mark.asyncio
    async def test_results_include_elapsed_ms(self):
        ev = StubEvaluator("timed", Action.ALLOW)
        chain = EvaluatorChain([ev])

        ctx = EvalContext(stage=Stage.TOOL_BEFORE, tool_name="exec")
        result = await chain.run(ctx)

        assert len(result.results) == 1
        assert "elapsed_ms" in result.results[0].metadata
        assert result.results[0].metadata["elapsed_ms"] >= 0
