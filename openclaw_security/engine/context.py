"""Evaluation context — the normalized event that all evaluators receive."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Stage(StrEnum):
    MESSAGE_BEFORE = "message.before"
    PARAMS_BEFORE = "params.before"
    TOOL_BEFORE = "tool.before"
    TOOL_AFTER = "tool.after"


class EvalContext(BaseModel):
    """Normalized representation of an OpenClaw interceptor event.

    Built from the raw JSON the TS shim sends over the socket.
    """

    stage: Stage
    session_id: str = ""
    channel: str = ""
    user_id: str = ""
    timestamp: float = Field(default_factory=lambda: __import__("time").time())

    # message.before
    message_text: str | None = None

    # tool.before / tool.after
    tool_name: str | None = None
    tool_args: dict[str, Any] = Field(default_factory=dict)
    tool_result: Any | None = None  # only populated on tool.after

    # params.before
    model: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)

    # raw event passthrough for evaluators that need full access
    raw: dict[str, Any] = Field(default_factory=dict)

    def flat_fields(self) -> dict[str, Any]:
        """Return a flattened dict suitable for pattern matching / Sigma / CEL."""
        flat: dict[str, Any] = {
            "stage": self.stage.value,
            "session_id": self.session_id,
            "channel": self.channel,
            "user_id": self.user_id,
            "timestamp": self.timestamp,
        }
        if self.message_text is not None:
            flat["message_text"] = self.message_text
        if self.tool_name is not None:
            flat["tool_name"] = self.tool_name
            flat.update({f"tool_args.{k}": v for k, v in self.tool_args.items()})
        if self.tool_result is not None:
            flat["tool_result"] = (
                str(self.tool_result) if not isinstance(self.tool_result, str) else self.tool_result
            )
        if self.model is not None:
            flat["model"] = self.model
        return flat

    def searchable_text(self) -> str:
        """Concatenate all text fields into one string for regex / ML scanning."""
        parts: list[str] = []
        if self.message_text:
            parts.append(self.message_text)
        for v in self.tool_args.values():
            if isinstance(v, str):
                parts.append(v)
        if isinstance(self.tool_result, str):
            parts.append(self.tool_result)
        return "\n".join(parts)
