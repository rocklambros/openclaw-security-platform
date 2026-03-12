"""Webhook reporter — sends evaluation results to an external endpoint."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import AggregatedResult

logger = logging.getLogger(__name__)


class WebhookReporter:
    """POST evaluation results to an external webhook URL."""

    def __init__(self, url: str, events: set[str] | None = None) -> None:
        self._url = url
        self.events: set[str] = events or {"block", "redact"}
        self._client = httpx.AsyncClient(timeout=5.0)

    async def send(self, ctx: EvalContext, result: AggregatedResult) -> None:
        payload = {
            "timestamp": ctx.timestamp,
            "stage": ctx.stage.value,
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            "channel": ctx.channel,
            "tool_name": ctx.tool_name,
            "action": result.action.value,
            "reasons": result.reasons,
            "evaluator_count": len(result.results),
        }
        try:
            resp = await self._client.post(
                self._url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code >= 400:
                logger.warning("Webhook returned %d: %s", resp.status_code, resp.text[:200])
        except Exception:
            logger.exception("Failed to send webhook to %s", self._url)

    async def close(self) -> None:
        await self._client.aclose()
