"""Regex evaluator — fast pattern matching against event fields."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, EvalResult
from openclaw_security.evaluators.base import Evaluator


@dataclass
class PatternEntry:
    """A single compiled pattern with an optional negate flag."""

    regex: re.Pattern[str]
    negate: bool = False
    field: str | None = None


@dataclass
class RegexRule:
    """A rule with one or more patterns combined via match mode."""

    label: str
    action: Action
    fields: list[str] | None
    patterns: list[PatternEntry] = field(default_factory=list)
    match: str = "any"  # "any" (OR) or "all" (AND)

    @staticmethod
    def from_config(raw: dict[str, Any]) -> "RegexRule":
        label = raw["label"]
        action = Action(raw.get("action", "block"))
        fields = raw.get("fields")
        match_mode = raw.get("match", "any")

        patterns: list[PatternEntry] = []

        if "pattern" in raw:
            # Single pattern shorthand (backward compatible)
            patterns.append(PatternEntry(regex=re.compile(raw["pattern"])))
        elif "patterns" in raw:
            for entry in raw["patterns"]:
                if isinstance(entry, str):
                    patterns.append(PatternEntry(regex=re.compile(entry)))
                elif isinstance(entry, dict):
                    patterns.append(
                        PatternEntry(
                            regex=re.compile(entry["pattern"]),
                            negate=entry.get("negate", False),
                            field=entry.get("field"),
                        )
                    )

        return RegexRule(
            label=label,
            action=action,
            fields=fields,
            patterns=patterns,
            match=match_mode,
        )


class RegexEvaluator(Evaluator):
    eval_type = "regex"
    """Matches compiled regex patterns against event text fields.

    Config shape::

        name: secrets-scanner
        type: regex
        stages: [tool.before, tool.after]
        rules:
          # Single pattern (backward compatible):
          - label: AWS Access Key
            pattern: "AKIA[0-9A-Z]{16}"
            action: redact

          # Compound AND — all patterns must match:
          - label: Network exfiltration
            patterns:
              - "curl|wget|nc"
              - "\\|.*base64"
            match: all
            action: block
            fields: [tool_args.command]

          # Compound with negation — X and not Y:
          - label: Unsafe rm without sudo
            patterns:
              - pattern: "rm\\s+-rf"
              - pattern: "sudo"
                negate: true
            match: all
            action: block

          # Per-pattern field targeting — different patterns against different fields:
          - label: API key outside safe path
            patterns:
              - pattern: "(?i)api[_-]?key\\s*[:=]"
                field: tool_args.content
              - pattern: "^/safe/"
                field: tool_args.file_path
                negate: true
            match: all
            action: block
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        super().__init__(name, config)
        self._rules: list[RegexRule] = []
        for r in config.get("rules", []):
            self._rules.append(RegexRule.from_config(r))

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
                matched, first_match = self._check_rule(rule, target, flat)
                if matched:
                    redacted = None
                    if rule.action == Action.REDACT:
                        redacted = target
                        for p in rule.patterns:
                            if not p.negate:
                                redacted = p.regex.sub("[REDACTED]", redacted)

                    return self._result(
                        action=rule.action,
                        reason=f"Regex match: {rule.label}",
                        redacted=redacted,
                        metadata={
                            "rule": rule.label,
                            "match": first_match[:200] if first_match else "",
                        },
                    )

        return self._result()

    @staticmethod
    def _check_rule(
        rule: RegexRule,
        target: str,
        flat: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None]:
        """Evaluate a rule's patterns against the target text.

        If a pattern specifies its own ``field``, the value is looked up from
        *flat* instead of using *target*.  This allows compound rules to check
        different patterns against different event fields.

        Returns (matched, first_match_text).
        """
        first_match: str | None = None
        results: list[bool] = []

        for p in rule.patterns:
            if p.field and flat:
                val = flat.get(p.field, "")
                t = val if isinstance(val, str) else str(val) if val is not None else ""
            else:
                t = target

            m = p.regex.search(t)
            hit = m is not None
            if p.negate:
                hit = not hit
            else:
                if m and first_match is None:
                    first_match = m.group()
            results.append(hit)

        if not results:
            return False, None

        if rule.match == "all":
            return all(results), first_match
        else:  # "any"
            return any(results), first_match
