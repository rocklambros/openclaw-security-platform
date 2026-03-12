"""Evaluation result types and aggregation logic."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"


class EvalResult(BaseModel):
    """Result from a single evaluator."""

    evaluator: str
    action: Action = Action.ALLOW
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str = ""
    redacted: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AggregatedResult(BaseModel):
    """Combined result from running the full evaluator chain."""

    action: Action = Action.ALLOW
    results: list[EvalResult] = Field(default_factory=list)
    redacted: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK

    @property
    def reasons(self) -> list[str]:
        return [r.reason for r in self.results if r.reason and r.action != Action.ALLOW]


def aggregate(results: list[EvalResult]) -> AggregatedResult:
    """Aggregate individual evaluator results into a final verdict.

    Priority: block > redact > warn > allow.
    If any evaluator blocks, the final action is block.
    """
    if not results:
        return AggregatedResult()

    ACTION_PRIORITY = {Action.BLOCK: 3, Action.REDACT: 2, Action.WARN: 1, Action.ALLOW: 0}

    final_action = Action.ALLOW
    final_redacted: str | None = None

    for r in results:
        if ACTION_PRIORITY[r.action] > ACTION_PRIORITY[final_action]:
            final_action = r.action
        if r.action == Action.REDACT and r.redacted is not None:
            final_redacted = r.redacted

    return AggregatedResult(
        action=final_action,
        results=results,
        redacted=final_redacted,
    )
