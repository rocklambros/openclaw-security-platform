"""Evaluator chain — runs evaluators in cost order with short-circuit on block."""

from __future__ import annotations

import logging
import time
from typing import Any

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, AggregatedResult, EvalResult, aggregate
from openclaw_security.evaluators.base import Evaluator

logger = logging.getLogger(__name__)

# Cost order: cheapest evaluator types first.
TYPE_COST_ORDER = {
    "regex": 0,
    "sigma": 1,
    "cel": 2,
    "sql": 3,
    "ml": 4,
    "llm": 5,
}


class EvaluatorChain:
    """Ordered chain of evaluators.  Runs cheapest first, short-circuits on block."""

    def __init__(self, evaluators: list[Evaluator] | None = None) -> None:
        self._evaluators: list[Evaluator] = []
        if evaluators:
            for e in evaluators:
                self.add(e)

    def add(self, evaluator: Evaluator) -> None:
        self._evaluators.append(evaluator)
        self._sort()

    def _sort(self) -> None:
        """Keep evaluators sorted by type cost so cheap ones run first."""
        self._evaluators.sort(
            key=lambda e: TYPE_COST_ORDER.get(e.eval_type, 99)
        )

    async def run(self, ctx: EvalContext) -> AggregatedResult:
        """Execute the evaluator chain against a context.

        Evaluators that don't match the current stage are skipped.
        A ``block`` result short-circuits — remaining evaluators are not run.
        """
        results: list[EvalResult] = []

        for evaluator in self._evaluators:
            if not evaluator.should_run(ctx):
                continue

            t0 = time.monotonic()
            try:
                result = await evaluator.evaluate(ctx)
            except Exception:
                logger.exception("Evaluator %s raised an exception", evaluator.name)
                result = EvalResult(
                    evaluator=evaluator.name,
                    action=Action.WARN,
                    confidence=0.0,
                    reason=f"Evaluator {evaluator.name} failed with an internal error",
                )
            elapsed_ms = (time.monotonic() - t0) * 1000

            logger.debug(
                "evaluator=%s action=%s confidence=%.2f elapsed=%.1fms",
                evaluator.name,
                result.action,
                result.confidence,
                elapsed_ms,
            )
            result.metadata["elapsed_ms"] = round(elapsed_ms, 1)
            results.append(result)

            if result.action == Action.BLOCK:
                logger.info(
                    "Short-circuit: %s blocked — skipping remaining evaluators",
                    evaluator.name,
                )
                break

        return aggregate(results)

    def __len__(self) -> int:
        return len(self._evaluators)

    def __repr__(self) -> str:
        names = [e.name for e in self._evaluators]
        return f"EvaluatorChain({names})"
