"""Sigma evaluator — structured threat detection using Sigma rules.

Maps OpenClaw interceptor events to Sigma log sources, then evaluates
Sigma rule conditions against the flattened event fields.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, EvalResult
from openclaw_security.evaluators.base import Evaluator

logger = logging.getLogger(__name__)


class SigmaConditionMatcher:
    """Lightweight Sigma condition matcher operating on flat dicts.

    Supports the core Sigma detection logic:
    - field equals / startswith / endswith / contains / re
    - selection + filter combos with ``and`` / ``or`` / ``not``

    For full pySigma pipeline integration, users can swap in SigmaCollection
    from the ``pysigma`` package.  This built-in matcher covers the common
    case without requiring a SIEM backend.
    """

    def __init__(self, detection: dict[str, Any]) -> None:
        self._selections: dict[str, Any] = {
            k: v for k, v in detection.items() if k != "condition"
        }
        self._condition: str = detection.get("condition", "")

    def matches(self, event: dict[str, Any]) -> bool:
        selection_results: dict[str, bool] = {}
        for sel_name, sel_def in self._selections.items():
            if isinstance(sel_def, dict):
                selection_results[sel_name] = self._match_selection(sel_def, event)
            elif isinstance(sel_def, list):
                # OR across list items
                selection_results[sel_name] = any(
                    self._match_selection(item, event) if isinstance(item, dict) else False
                    for item in sel_def
                )
            else:
                selection_results[sel_name] = False

        return self._eval_condition(self._condition, selection_results)

    def _match_selection(self, sel: dict[str, Any], event: dict[str, Any]) -> bool:
        for field_expr, expected in sel.items():
            field, modifier = self._parse_field(field_expr)
            actual = event.get(field)
            if actual is None:
                return False
            if not self._compare(str(actual), expected, modifier):
                return False
        return True

    @staticmethod
    def _parse_field(field_expr: str) -> tuple[str, str]:
        if "|" in field_expr:
            parts = field_expr.split("|")
            return parts[0], parts[1]
        return field_expr, "equals"

    @staticmethod
    def _compare(actual: str, expected: Any, modifier: str) -> bool:
        values = expected if isinstance(expected, list) else [expected]
        for v in values:
            v_str = str(v)
            match modifier:
                case "startswith":
                    if actual.startswith(v_str):
                        return True
                case "endswith":
                    if actual.endswith(v_str):
                        return True
                case "contains":
                    if v_str in actual:
                        return True
                case "re":
                    import re
                    if re.search(v_str, actual):
                        return True
                case _:  # equals
                    if actual == v_str:
                        return True
        return False

    @staticmethod
    def _eval_condition(condition: str, results: dict[str, bool]) -> bool:
        if not condition:
            return all(results.values()) if results else False

        # Simple expression evaluator for: selection, selection and filter,
        # selection and not filter, 1 of selection*
        cond = condition.strip()

        if cond.startswith("1 of "):
            prefix = cond[5:].rstrip("*")
            return any(v for k, v in results.items() if k.startswith(prefix))

        if cond.startswith("all of "):
            prefix = cond[7:].rstrip("*")
            matching = [v for k, v in results.items() if k.startswith(prefix)]
            return all(matching) if matching else False

        # Handle "selection and not filter", "selection or filter", "selection"
        parts = cond.split()
        if len(parts) == 1:
            return results.get(parts[0], False)
        if len(parts) == 3 and parts[1] == "and":
            if parts[2].startswith("not ") or (len(parts) == 4 and parts[2] == "not"):
                pass
            return results.get(parts[0], False) and results.get(parts[2], False)
        if len(parts) == 4 and parts[1] == "and" and parts[2] == "not":
            return results.get(parts[0], False) and not results.get(parts[3], False)
        if len(parts) == 3 and parts[1] == "or":
            return results.get(parts[0], False) or results.get(parts[2], False)

        # Fallback: all must match
        return all(results.values()) if results else False


class SigmaRule:
    __slots__ = ("title", "level", "action", "matcher")

    def __init__(self, raw: dict[str, Any]) -> None:
        self.title: str = raw.get("title", "Untitled")
        self.level: str = raw.get("level", "medium")
        self.action = Action.BLOCK if self.level in ("critical", "high") else Action.DETECT
        detection = raw.get("detection", {})
        self.matcher = SigmaConditionMatcher(detection)


class SigmaEvaluator(Evaluator):
    eval_type = "sigma"
    """Load Sigma YAML rules and match them against OpenClaw events.

    Config shape::

        name: sigma-threats
        type: sigma
        stages: [tool.before, tool.after]
        rules_dir: ./rules/sigma/
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        super().__init__(name, config)
        self._rules: list[SigmaRule] = []
        rules_dir = config.get("rules_dir")
        if rules_dir:
            self._load_dir(Path(rules_dir))
        for inline in config.get("rules", []):
            self._rules.append(SigmaRule(inline))

    def _load_dir(self, path: Path) -> None:
        if not path.is_dir():
            logger.warning("Sigma rules_dir not found: %s", path)
            return
        for f in sorted(path.glob("**/*.yaml")) + sorted(path.glob("**/*.yml")):
            try:
                with open(f) as fh:
                    for raw in yaml.safe_load_all(fh):
                        if raw and isinstance(raw, dict) and "detection" in raw:
                            self._rules.append(SigmaRule(raw))
            except Exception:
                logger.exception("Failed to load Sigma rule: %s", f)

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        event = ctx.flat_fields()

        for rule in self._rules:
            if rule.matcher.matches(event):
                return self._result(
                    action=rule.action,
                    reason=f"Sigma rule matched: {rule.title}",
                    metadata={"rule": rule.title, "level": rule.level},
                )

        return self._result()
