"""Abstract base class for all evaluators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action, EvalResult


class Evaluator(ABC):
    """Base evaluator interface.

    Every evaluator type (regex, sigma, cel, sql, ml, llm) must subclass this
    and implement ``evaluate``.  The ``stages`` property declares which
    interceptor stages this evaluator should run at.
    """

    # Override in subclasses for explicit cost ordering in the chain.
    eval_type: str = "unknown"

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        self.name = name
        self._config = config
        self._stages: set[Stage] = {
            Stage(s) for s in config.get("stages", ["tool.before", "tool.after"])
        }

    @property
    def stages(self) -> set[Stage]:
        return self._stages

    def should_run(self, ctx: EvalContext) -> bool:
        """Return True if this evaluator is relevant for the given context."""
        return ctx.stage in self._stages

    @abstractmethod
    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        """Run the evaluator against the given context.

        Must return an EvalResult — never raise on expected conditions.
        """
        ...

    def _result(
        self,
        action: Action = Action.ALLOW,
        confidence: float = 1.0,
        reason: str = "",
        **kwargs: Any,
    ) -> EvalResult:
        """Helper to build a result stamped with this evaluator's name."""
        return EvalResult(
            evaluator=self.name,
            action=action,
            confidence=confidence,
            reason=reason,
            **kwargs,
        )
