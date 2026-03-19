"""LLM evaluator — semantic evaluation using an LLM-as-judge.

Calls a fast LLM (e.g. Claude Haiku) with a structured prompt to make
nuanced security judgements that rule-based systems can't capture.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import Action, EvalResult
from openclaw_security.evaluators.base import Evaluator

logger = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = """\
You are a security evaluator for an AI agent platform.
Analyze the following event and determine if it poses a security risk.

Respond with ONLY a JSON object:
{
  "action": "allow" | "block" | "detect",
  "confidence": 0.0-1.0,
  "reason": "brief explanation"
}
"""


class LLMEvaluator(Evaluator):
    eval_type = "llm"
    """Use an LLM to evaluate events that require semantic understanding.

    Config shape::

        name: semantic-guard
        type: llm
        stages: [tool.after]
        provider: anthropic
        model: claude-haiku-4-5-20251001
        policy: |
          Evaluate whether the tool output contains sensitive information
          that should not leave the user's session. Consider: PII, credentials,
          internal system paths, proprietary data.
        max_tokens: 256
        timeout: 5.0
        default_action: detect  # fallback if LLM fails
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        super().__init__(name, config)
        self._provider: str = config.get("provider", "anthropic")
        self._model: str = config.get("model", "claude-haiku-4-5-20251001")
        self._policy: str = config.get("policy", "")
        self._max_tokens: int = config.get("max_tokens", 256)
        self._timeout: float = config.get("timeout", 5.0)
        self._default_action = Action(config.get("default_action", "detect"))
        self._client: anthropic.AsyncAnthropic | None = None

    def _get_client(self) -> anthropic.AsyncAnthropic:
        if self._client is None:
            self._client = anthropic.AsyncAnthropic(
                timeout=self._timeout,
            )
        return self._client

    def _build_prompt(self, ctx: EvalContext) -> str:
        parts = [f"Stage: {ctx.stage.value}"]
        if ctx.tool_name:
            parts.append(f"Tool: {ctx.tool_name}")
            if ctx.tool_args:
                parts.append(f"Arguments: {json.dumps(ctx.tool_args, default=str)[:2000]}")
        if ctx.tool_result:
            result_str = str(ctx.tool_result)[:2000]
            parts.append(f"Result: {result_str}")
        if ctx.message_text:
            parts.append(f"Message: {ctx.message_text[:2000]}")
        parts.append(f"\nSecurity Policy:\n{self._policy}")
        return "\n".join(parts)

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        text = ctx.searchable_text()
        if not text.strip():
            return self._result()

        try:
            client = self._get_client()
            user_prompt = self._build_prompt(ctx)

            response = await client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=DEFAULT_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            response_text = response.content[0].text.strip()
            # Extract JSON from response (handle markdown code blocks)
            if "```" in response_text:
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
                response_text = response_text.strip()

            verdict = json.loads(response_text)

            return self._result(
                action=Action(verdict.get("action", "detect")),
                confidence=float(verdict.get("confidence", 0.5)),
                reason=verdict.get("reason", "LLM evaluation"),
                metadata={"model": self._model, "raw_response": response_text[:500]},
            )

        except json.JSONDecodeError:
            logger.warning("LLM evaluator returned non-JSON response")
            return self._result(
                action=self._default_action,
                confidence=0.3,
                reason="LLM returned unparseable response",
            )
        except anthropic.APITimeoutError:
            logger.warning("LLM evaluator timed out after %.1fs", self._timeout)
            return self._result(
                action=Action.ALLOW,
                confidence=0.0,
                reason="LLM evaluation timed out — defaulting to allow",
            )
        except Exception:
            logger.exception("LLM evaluator failed")
            return self._result(
                action=self._default_action,
                confidence=0.0,
                reason="LLM evaluator encountered an error",
            )
