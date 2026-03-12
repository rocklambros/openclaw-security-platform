"""Evaluation server — FastAPI over HTTP / Unix socket.

The TS shim plugin forwards OpenClaw interceptor events here.
We run the evaluator chain and return a verdict.
"""

from __future__ import annotations

import argparse
import logging
import sys
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, Field

from openclaw_security.config.loader import build_chain, load_config
from openclaw_security.config.schema import PlatformConfig
from openclaw_security.engine.chain import EvaluatorChain
from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action, AggregatedResult
from openclaw_security.reporting.logger import AuditLogger
from openclaw_security.reporting.webhook import WebhookReporter

logger = logging.getLogger("openclaw_security")


# --- Global state (set during lifespan) ---

_chain: EvaluatorChain | None = None
_config: PlatformConfig | None = None
_audit: AuditLogger | None = None
_webhook: WebhookReporter | None = None


# --- Request / Response models ---


class EvaluateRequest(BaseModel):
    stage: Stage
    session_id: str = ""
    channel: str = ""
    user_id: str = ""
    timestamp: float | None = None
    message_text: str | None = None
    tool_name: str | None = None
    tool_args: dict[str, Any] = Field(default_factory=dict)
    tool_result: Any | None = None
    model: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    action: str
    blocked: bool
    reasons: list[str]
    redacted: str | None = None
    results: list[dict[str, Any]]


# --- App ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _chain, _config, _audit, _webhook
    # Skip loading if already configured (e.g. in tests)
    if _chain is not None:
        yield
        return
    config_path = getattr(app.state, "config_path", None)
    _config = load_config(config_path)
    _chain = build_chain(_config)

    if _config.reporting.log_file:
        _audit = AuditLogger(_config.reporting.log_file)
    if _config.reporting.webhook_url:
        _webhook = WebhookReporter(
            url=_config.reporting.webhook_url,
            events=set(_config.reporting.webhook_events),
        )

    logger.info(
        "OpenClaw Security Platform started — %d evaluators loaded",
        len(_chain),
    )
    yield
    logger.info("Shutting down")


app = FastAPI(title="OpenClaw Security Platform", version="0.1.0", lifespan=lifespan)


@app.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest) -> EvaluateResponse:
    """Run the evaluator chain against an interceptor event."""
    assert _chain is not None, "Server not initialized"

    ctx = EvalContext(
        stage=req.stage,  # type: ignore[arg-type]
        session_id=req.session_id,
        channel=req.channel,
        user_id=req.user_id,
        message_text=req.message_text,
        tool_name=req.tool_name,
        tool_args=req.tool_args,
        tool_result=req.tool_result,
        model=req.model,
        params=req.params,
        raw=req.raw,
    )
    if req.timestamp is not None:
        ctx.timestamp = req.timestamp

    result: AggregatedResult = await _chain.run(ctx)

    # Side-effects: audit log + webhook
    if _audit:
        _audit.log(ctx, result)
    if _webhook and result.action.value in (_webhook.events or set()):
        await _webhook.send(ctx, result)

    return EvaluateResponse(
        action=result.action.value,
        blocked=result.blocked,
        reasons=result.reasons,
        redacted=result.redacted,
        results=[r.model_dump() for r in result.results],
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "evaluators": len(_chain) if _chain else 0,
    }


def main():
    parser = argparse.ArgumentParser(description="OpenClaw Security Platform")
    parser.add_argument("-c", "--config", help="Path to config YAML")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--socket", default=None, help="Unix socket path")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    app.state.config_path = args.config
    config = load_config(args.config)

    host = args.host or config.server.host
    port = args.port or config.server.port
    socket_path = args.socket or config.server.unix_socket

    if socket_path:
        logger.info("Listening on unix socket: %s", socket_path)
        uvicorn.run(app, uds=socket_path, log_level=args.log_level)
    else:
        logger.info("Listening on http://%s:%d", host, port)
        uvicorn.run(app, host=host, port=port, log_level=args.log_level)


if __name__ == "__main__":
    main()
