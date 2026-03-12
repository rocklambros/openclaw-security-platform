"""Audit logger — writes all evaluation results to a structured log file."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import AggregatedResult

logger = logging.getLogger(__name__)


class AuditLogger:
    """Append-only JSON-lines audit log."""

    def __init__(self, log_file: str) -> None:
        self._path = Path(log_file)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a")

    def log(self, ctx: EvalContext, result: AggregatedResult) -> None:
        entry = {
            "timestamp": ctx.timestamp,
            "stage": ctx.stage.value,
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            "channel": ctx.channel,
            "tool_name": ctx.tool_name,
            "action": result.action.value,
            "blocked": result.blocked,
            "reasons": result.reasons,
            "evaluator_results": [
                {
                    "evaluator": r.evaluator,
                    "action": r.action.value,
                    "confidence": r.confidence,
                    "reason": r.reason,
                    "elapsed_ms": r.metadata.get("elapsed_ms"),
                }
                for r in result.results
            ],
        }
        try:
            self._fh.write(json.dumps(entry) + "\n")
            self._fh.flush()
        except Exception:
            logger.exception("Failed to write audit log entry")

    def close(self) -> None:
        self._fh.close()
