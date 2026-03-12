"""Regex evaluator — fast pattern matching against event fields."""

from __future__ import annotations

import re
from typing import Any

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, EvalResult
from openclaw_security.evaluators.base import Evaluator


class RegexRule:
    __slots__ = ("label", "pattern", "action", "fields")

    def __init__(self, label: str, pattern: str, action: Action, fields: list[str] | None) -> None:
        self.label = label
        self.pattern = re.compile(pattern)
        self.action = action
        # Which context fields to scan. None = scan searchable_text (all text).
        self.fields = fields


class RegexEvaluator(Evaluator):
    eval_type = "regex"
    """Matches compiled regex patterns against event text fields.

    Config shape::

        name: secrets-scanner
        type: regex
        stages: [tool.before, tool.after]
        rules:
          - label: AWS Access Key
            pattern: "AKIA[0-9A-Z]{16}"
            action: redact
          - label: Destructive rm
            pattern: "rm\\s+-rf\\s+/"
            action: block
            fields: [tool_args.command]
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        super().__init__(name, config)
        self._rules: list[RegexRule] = []
        for r in config.get("rules", []):
            self._rules.append(
                RegexRule(
                    label=r["label"],
                    pattern=r["pattern"],
                    action=Action(r.get("action", "block")),
                    fields=r.get("fields"),
                )
            )

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        flat = ctx.flat_fields()
        full_text = ctx.searchable_text()

        for rule in self._rules:
            targets: list[str] = []
            if rule.fields:
                for f in rule.fields:
                    val = flat.get(f)
                    if isinstance(val, str):
                        targets.append(val)
            else:
                targets.append(full_text)

            for target in targets:
                match = rule.pattern.search(target)
                if match:
                    redacted = None
                    if rule.action == Action.REDACT:
                        redacted = rule.pattern.sub("[REDACTED]", target)

                    return self._result(
                        action=rule.action,
                        reason=f"Regex match: {rule.label}",
                        redacted=redacted,
                        metadata={"rule": rule.label, "match": match.group()[:200]},
                    )

        return self._result()
