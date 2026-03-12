"""CEL evaluator — Common Expression Language policy rules.

Uses celpy to evaluate CEL expressions against the flattened event context.
More powerful than regex, cheaper than ML — ideal for conditional policies.
"""

from __future__ import annotations

import logging
from typing import Any

import celpy
from celpy import celtypes

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, EvalResult
from openclaw_security.evaluators.base import Evaluator

logger = logging.getLogger(__name__)


def _to_cel_value(v: Any) -> celtypes.Value:
    """Convert a Python value to a CEL value."""
    if isinstance(v, bool):
        return celtypes.BoolType(v)
    if isinstance(v, int):
        return celtypes.IntType(v)
    if isinstance(v, float):
        return celtypes.DoubleType(v)
    if isinstance(v, str):
        return celtypes.StringType(v)
    if isinstance(v, list):
        return celtypes.ListType([_to_cel_value(i) for i in v])
    return celtypes.StringType(str(v))


class CELRule:
    __slots__ = ("label", "program", "action", "reason")

    def __init__(self, label: str, expr: str, action: Action, reason: str) -> None:
        self.label = label
        self.action = action
        self.reason = reason
        env = celpy.Environment()
        ast = env.compile(expr)
        self.program = env.program(ast)


class CELEvaluator(Evaluator):
    eval_type = "cel"
    """Evaluate CEL expressions against flattened event context.

    Config shape::

        name: access-policies
        type: cel
        stages: [tool.before]
        rules:
          - label: block-curl-non-admin
            expr: >
              tool_name == "exec" &&
              tool_args_command.contains("curl") &&
              user_id != "admin"
            action: block
            reason: Unapproved network access
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        super().__init__(name, config)
        self._rules: list[CELRule] = []
        for r in config.get("rules", []):
            try:
                self._rules.append(
                    CELRule(
                        label=r.get("label", "unnamed"),
                        expr=r["expr"],
                        action=Action(r.get("action", "block")),
                        reason=r.get("reason", ""),
                    )
                )
            except Exception:
                logger.exception("Failed to compile CEL rule: %s", r.get("label"))

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        flat = ctx.flat_fields()
        # CEL uses dotless keys — replace dots with underscores
        activation: dict[str, celtypes.Value] = {}
        for k, v in flat.items():
            cel_key = k.replace(".", "_")
            activation[cel_key] = _to_cel_value(v)

        for rule in self._rules:
            try:
                result = rule.program.evaluate(activation)
                if result == celtypes.BoolType(True):
                    return self._result(
                        action=rule.action,
                        reason=rule.reason or f"CEL policy triggered: {rule.label}",
                        metadata={"rule": rule.label},
                    )
            except celpy.CELEvalError:
                # Expression references fields not in this event — skip
                continue
            except Exception:
                logger.exception("CEL rule %s failed", rule.label)
                continue

        return self._result()
