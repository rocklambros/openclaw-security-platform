"""Configuration schema — validated with Pydantic."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class EvaluatorConfig(BaseModel):
    """Configuration for a single evaluator instance."""

    name: str
    type: Literal["regex", "sigma", "cel", "sql", "ml", "llm"]
    enabled: bool = True
    stages: list[str] = Field(default=["tool.before", "tool.after"])

    # Type-specific config is passed through as a dict.
    # Each evaluator class validates its own fields.
    rules: list[dict[str, Any]] = Field(default_factory=list)
    rules_dir: str | None = None

    # ML-specific
    model_path: str | None = None
    threshold: float | None = None
    tokenizer: str | None = None
    max_length: int | None = None

    # LLM-specific
    provider: str | None = None
    model: str | None = None
    policy: str | None = None
    max_tokens: int | None = None
    timeout: float | None = None
    default_action: str | None = None

    # Generic
    action: str | None = None
    label: str | None = None

    def to_evaluator_dict(self) -> dict[str, Any]:
        """Flatten to a dict the evaluator constructor expects."""
        return {k: v for k, v in self.model_dump().items() if v is not None}


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 9920
    unix_socket: str | None = None  # prefer unix socket if set


class ReportingConfig(BaseModel):
    log_file: str | None = None
    webhook_url: str | None = None
    webhook_events: list[str] = Field(default=["block", "redact"])


class PlatformConfig(BaseModel):
    """Root configuration for the OpenClaw Security Platform."""

    server: ServerConfig = Field(default_factory=ServerConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    evaluators: list[EvaluatorConfig] = Field(default_factory=list)
