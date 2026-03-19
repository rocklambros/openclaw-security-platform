"""Anthropic API reverse proxy — full blocking at every stage.

Sits between OpenClaw and api.anthropic.com.  Intercepts all Messages API
traffic and runs the evaluator chain on:

  1. Inbound user messages   (message.before)  — can block the entire request
  2. Tool-use blocks         (tool.before)     — can strip dangerous tool calls
  3. Tool-result blocks      (tool.after)      — can redact secrets before Claude sees them

OpenClaw connects to this proxy via the ``models.providers`` custom-provider
mechanism (set ``baseUrl`` to point here).  The proxy forwards allowed traffic
to the real Anthropic API transparently.
"""

from __future__ import annotations

import json
import logging
import time as _time
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse, JSONResponse

from openclaw_security.engine.chain import EvaluatorChain
from openclaw_security.engine.context import EvalContext, Stage
from openclaw_security.engine.result import Action, AggregatedResult

logger = logging.getLogger("openclaw_security.proxy")

UPSTREAM_BASE = "https://api.anthropic.com"

router = APIRouter()

# These will be set by server.py during lifespan
_chain: EvaluatorChain | None = None
_report_fn: Any = None  # callback(ctx, result, elapsed_ms) for audit/dashboard


def configure(chain: EvaluatorChain, report_fn: Any = None) -> None:
    """Called by server.py to inject the evaluator chain."""
    global _chain, _report_fn
    _chain = chain
    _report_fn = report_fn


async def _evaluate(stage: Stage, **kwargs: Any) -> AggregatedResult:
    """Run the evaluator chain and report the result."""
    assert _chain is not None
    ctx = EvalContext(stage=stage, **kwargs)
    t0 = _time.monotonic()
    result = await _chain.run(ctx)
    elapsed_ms = (_time.monotonic() - t0) * 1000
    if _report_fn:
        await _report_fn(ctx, result, elapsed_ms)
    return result


def _extract_user_messages(body: dict) -> list[str]:
    """Pull user-authored text from the LAST user message only.

    Each API call sends the full conversation history.  We only evaluate the
    most recent user turn — older messages were already evaluated on previous
    calls.
    """
    texts: list[str] = []
    # Find the last user message
    last_user_msg = None
    for msg in body.get("messages", []):
        if msg.get("role") == "user":
            last_user_msg = msg
    if last_user_msg is None:
        return texts

    content = last_user_msg.get("content", "")
    if isinstance(content, str):
        texts.append(content)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    texts.append(block.get("text", ""))
    return texts


def _extract_tool_results(body: dict) -> list[dict]:
    """Extract tool_result blocks from the LAST user message only.

    Each API call sends the full conversation history.  We only evaluate tool
    results from the most recent user turn — older ones were already evaluated.
    """
    results: list[dict] = []
    # Find the last user message
    last_user_msg = None
    for msg in body.get("messages", []):
        if msg.get("role") == "user":
            last_user_msg = msg
    if last_user_msg is None:
        return results

    content = last_user_msg.get("content", "")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                results.append(block)
    return results


def _extract_tool_uses(body: dict) -> list[dict]:
    """Extract tool_use blocks from a non-streaming response."""
    tool_uses: list[dict] = []
    for block in body.get("content", []):
        if isinstance(block, dict) and block.get("type") == "tool_use":
            tool_uses.append(block)
    return tool_uses


async def _check_messages(body: dict) -> AggregatedResult | None:
    """Evaluate user messages at message.before stage. Returns result if blocked."""
    texts = _extract_user_messages(body)
    if not texts:
        return None
    combined = "\n".join(texts)
    result = await _evaluate(
        Stage.MESSAGE_BEFORE,
        message_text=combined,
        session_id=body.get("metadata", {}).get("session_id", ""),
    )
    if result.blocked:
        return result
    return None


async def _check_tool_results(body: dict) -> AggregatedResult | None:
    """Evaluate tool results at tool.after stage (before Claude sees them)."""
    tool_results = _extract_tool_results(body)
    if not tool_results:
        return None

    # Build a map of tool_use_id -> tool_name from assistant messages
    tool_id_to_name: dict[str, str] = {}
    for msg in body.get("messages", []):
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    tool_id_to_name[block.get("id", "")] = block.get("name", "")

    worst: AggregatedResult | None = None
    for tr in tool_results:
        content = tr.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
            )
        if not content:
            continue
        tool_use_id = tr.get("tool_use_id", "")
        tool_name = tool_id_to_name.get(tool_use_id, tool_use_id)
        result = await _evaluate(
            Stage.TOOL_AFTER,
            tool_name=tool_name,
            tool_result=content,
            session_id=body.get("metadata", {}).get("session_id", ""),
        )
        if result.blocked:
            return result
        if worst is None or result.action.value > (worst.action.value if worst else "allow"):
            worst = result
    return worst if worst and worst.action != Action.ALLOW else None


async def _check_tool_uses(response_body: dict) -> tuple[list[dict], list[str]]:
    """Evaluate tool_use blocks at tool.before. Returns (kept_content, reasons)."""
    content = response_body.get("content", [])
    kept: list[dict] = []
    all_reasons: list[str] = []

    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            kept.append(block)
            continue

        result = await _evaluate(
            Stage.TOOL_BEFORE,
            tool_name=block.get("name", ""),
            tool_args=block.get("input", {}),
            session_id=response_body.get("metadata", {}).get("session_id", ""),
        )

        if result.blocked:
            reason = "; ".join(result.reasons) or "Blocked by security policy"
            all_reasons.append(f"Blocked tool '{block.get('name')}': {reason}")
            # Replace tool_use with a text block explaining the block
            kept.append({
                "type": "text",
                "text": f"[SECURITY] Tool call '{block.get('name')}' was blocked: {reason}",
            })
        else:
            kept.append(block)

    return kept, all_reasons


def _blocked_response(result: AggregatedResult, stage: str, streaming: bool = False):
    """Build a response when a request is blocked (JSON or SSE depending on mode)."""
    reason = "; ".join(result.reasons) or "Blocked by security policy"
    block_text = f"[SECURITY BLOCK — {stage}] {reason}"

    if not streaming:
        return JSONResponse(
            status_code=200,
            content={
                "id": "msg_blocked",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": block_text}],
                "model": "security-proxy",
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        )

    # Return a well-formed SSE stream that OpenClaw can parse
    # NOTE: OpenClaw only parses "data: {...}" lines — NOT "event: ..." prefix format.
    async def generate():
        msg_start = {
            "type": "message_start",
            "message": {
                "id": "msg_blocked",
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": "security-proxy",
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        }
        yield f"data: {json.dumps(msg_start)}\n\n"

        block_start = {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        }
        yield f"data: {json.dumps(block_start)}\n\n"

        delta = {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": block_text},
        }
        yield f"data: {json.dumps(delta)}\n\n"

        block_stop = {"type": "content_block_stop", "index": 0}
        yield f"data: {json.dumps(block_stop)}\n\n"

        msg_delta = {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": 0},
        }
        yield f"data: {json.dumps(msg_delta)}\n\n"

        msg_stop = {"type": "message_stop"}
        yield f"data: {json.dumps(msg_stop)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


# ---------------------------------------------------------------------------
# Streaming support
# ---------------------------------------------------------------------------


async def _proxy_streaming_raw(
    request: Request, body: dict, upstream_headers: dict
) -> StreamingResponse:
    """Raw byte passthrough — zero processing, just forward Anthropic's stream."""
    client = httpx.AsyncClient(timeout=300.0)

    async def generate():
        try:
            async with client.stream(
                "POST",
                f"{UPSTREAM_BASE}/v1/messages",
                headers=upstream_headers,
                content=json.dumps(body),
            ) as upstream:
                async for chunk in upstream.aiter_bytes():
                    yield chunk
        except Exception as e:
            logger.exception("Proxy streaming error")
        finally:
            await client.aclose()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


async def _proxy_streaming(
    request: Request, body: dict, upstream_headers: dict
) -> StreamingResponse:
    """Forward a streaming request, buffering tool_use blocks for evaluation.

    Processes complete SSE records (delimited by ``\\n\\n``) to keep
    ``event:`` + ``data:`` pairs together.  Non-tool records are forwarded
    verbatim (preserving Anthropic's exact framing).  Tool_use records are
    buffered, evaluated, and either flushed or replaced.
    """
    client = httpx.AsyncClient(timeout=300.0)

    async def generate():
        current_tool_index: str | None = None
        current_tool_name: str = ""
        current_tool_json: str = ""
        buffered_records: list[bytes] = []  # raw SSE records for one tool_use block
        any_tool_allowed: bool = False
        buf = b""  # accumulates bytes until we have complete SSE records

        try:
            async with client.stream(
                "POST",
                f"{UPSTREAM_BASE}/v1/messages",
                headers=upstream_headers,
                content=json.dumps(body),
            ) as upstream:
                if upstream.status_code != 200:
                    error_body = b""
                    async for chunk in upstream.aiter_bytes():
                        error_body += chunk
                    try:
                        err = json.loads(error_body)
                    except Exception:
                        err = {"type": "error", "error": {"type": "api_error", "message": error_body.decode(errors="replace")}}
                    yield f"data: {json.dumps(err)}\n\n".encode()
                    return

                async for chunk in upstream.aiter_bytes():
                    buf += chunk

                    # Process all complete SSE records (separated by \n\n)
                    while b"\n\n" in buf:
                        record_end = buf.index(b"\n\n") + 2
                        record = buf[:record_end]  # includes trailing \n\n
                        buf = buf[record_end:]

                        # Extract the data: line from this record
                        parsed_evt = None
                        for rec_line in record.split(b"\n"):
                            text = rec_line.decode(errors="replace").rstrip("\r")
                            if text.startswith("data: "):
                                try:
                                    parsed_evt = json.loads(text[6:])
                                except Exception:
                                    pass
                                break

                        event_type = parsed_evt.get("type", "") if parsed_evt else ""

                        # --- Not in tool buffering mode ---
                        if current_tool_index is None:
                            if (
                                event_type == "content_block_start"
                                and parsed_evt.get("content_block", {}).get("type") == "tool_use"
                            ):
                                # Start buffering this tool_use block
                                current_tool_index = str(parsed_evt.get("index", ""))
                                current_tool_name = parsed_evt.get("content_block", {}).get("name", "")
                                current_tool_json = ""
                                buffered_records = [record]
                                continue

                            # Regular record — forward verbatim
                            yield record
                            continue

                        # --- In tool buffering mode ---
                        buffered_records.append(record)

                        if event_type == "content_block_delta":
                            delta = parsed_evt.get("delta", {}) if parsed_evt else {}
                            if delta.get("type") == "input_json_delta":
                                current_tool_json += delta.get("partial_json", "")

                        elif event_type == "content_block_stop":
                            # Tool block complete — evaluate
                            try:
                                tool_input = json.loads(current_tool_json) if current_tool_json else {}
                            except json.JSONDecodeError:
                                tool_input = {}

                            result = await _evaluate(
                                Stage.TOOL_BEFORE,
                                tool_name=current_tool_name,
                                tool_args=tool_input,
                            )

                            if result.blocked:
                                reason = "; ".join(result.reasons) or "Blocked by security policy"
                                logger.warning(
                                    "Proxy blocked tool '%s': %s", current_tool_name, reason
                                )
                                block_text = f"[SECURITY] Tool '{current_tool_name}' blocked: {reason}"
                                idx = int(current_tool_index)
                                replacement = (
                                    f"event: content_block_start\n"
                                    f"data: {{\"type\":\"content_block_start\",\"index\":{idx},"
                                    f"\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n"
                                    f"event: content_block_delta\n"
                                    f"data: {{\"type\":\"content_block_delta\",\"index\":{idx},"
                                    f"\"delta\":{{\"type\":\"text_delta\",\"text\":{json.dumps(block_text)}}}}}\n\n"
                                    f"event: content_block_stop\n"
                                    f"data: {{\"type\":\"content_block_stop\",\"index\":{idx}}}\n\n"
                                )
                                yield replacement.encode()
                            else:
                                any_tool_allowed = True
                                for rec in buffered_records:
                                    yield rec

                            current_tool_index = None
                            current_tool_name = ""
                            current_tool_json = ""
                            buffered_records = []

                # Flush remaining buffer (incomplete record or trailing data)
                if buf.strip():
                    if current_tool_index is None:
                        # Rewrite stop_reason if all tools were blocked
                        if not any_tool_allowed and b'"stop_reason":"tool_use"' in buf:
                            buf = buf.replace(b'"stop_reason":"tool_use"', b'"stop_reason":"end_turn"')
                        elif not any_tool_allowed and b'"stop_reason": "tool_use"' in buf:
                            buf = buf.replace(b'"stop_reason": "tool_use"', b'"stop_reason": "end_turn"')
                        yield buf

        except Exception as e:
            logger.exception("Proxy streaming error")
            yield f"data: {{\"type\":\"error\",\"error\":{{\"type\":\"proxy_error\",\"message\":\"{e}\"}}}}\n".encode()
        finally:
            await client.aclose()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.api_route("/anthropic/v1/messages", methods=["POST"])
async def proxy_messages(request: Request) -> Any:
    """Main proxy endpoint — intercepts Anthropic Messages API calls."""
    assert _chain is not None, "Proxy not initialized — call configure() first"

    raw_body = await request.body()
    body = json.loads(raw_body)
    is_streaming = body.get("stream", False)

    # --- Stage 1: Evaluate user messages (message.before) ---
    block_result = await _check_messages(body)
    if block_result:
        logger.warning("Proxy blocked request at message.before: %s", block_result.reasons)
        return _blocked_response(block_result, "message.before", streaming=is_streaming)

    # --- Stage 2: Evaluate tool results in request (tool.after) ---
    tool_result_check = await _check_tool_results(body)
    if tool_result_check and tool_result_check.blocked:
        logger.warning("Proxy blocked request at tool.after: %s", tool_result_check.reasons)
        return _blocked_response(tool_result_check, "tool.after", streaming=is_streaming)

    # --- Forward to Anthropic ---
    # Pass through auth and other headers
    upstream_headers = {
        "Content-Type": "application/json",
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
    }
    # Forward API key from request
    if "x-api-key" in request.headers:
        upstream_headers["x-api-key"] = request.headers["x-api-key"]
    if "authorization" in request.headers:
        upstream_headers["authorization"] = request.headers["authorization"]
    # Forward anthropic-beta if present
    if "anthropic-beta" in request.headers:
        upstream_headers["anthropic-beta"] = request.headers["anthropic-beta"]

    # --- Streaming ---
    if is_streaming:
        return await _proxy_streaming(request, body, upstream_headers)

    # --- Non-streaming ---
    async with httpx.AsyncClient(timeout=300.0) as client:
        upstream_resp = await client.post(
            f"{UPSTREAM_BASE}/v1/messages",
            headers=upstream_headers,
            content=json.dumps(body),
        )

    if upstream_resp.status_code != 200:
        return JSONResponse(
            status_code=upstream_resp.status_code,
            content=upstream_resp.json(),
        )

    response_body = upstream_resp.json()

    # --- Stage 3: Evaluate tool_use blocks in response (tool.before) ---
    kept_content, block_reasons = await _check_tool_uses(response_body)
    if block_reasons:
        logger.warning("Proxy modified response at tool.before: %s", block_reasons)
        response_body["content"] = kept_content
        # If ALL tool_use blocks were removed, update stop_reason
        has_tool_use = any(
            b.get("type") == "tool_use" for b in kept_content if isinstance(b, dict)
        )
        if not has_tool_use and response_body.get("stop_reason") == "tool_use":
            response_body["stop_reason"] = "end_turn"

    return JSONResponse(content=response_body)


@router.api_route("/anthropic/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_passthrough(request: Request, path: str) -> Any:
    """Pass through non-messages endpoints (models, etc.) without evaluation."""
    raw_body = await request.body()
    upstream_headers = dict(request.headers)
    upstream_headers.pop("host", None)

    async with httpx.AsyncClient(timeout=60.0) as client:
        upstream_resp = await client.request(
            method=request.method,
            url=f"{UPSTREAM_BASE}/v1/{path}",
            headers=upstream_headers,
            content=raw_body if raw_body else None,
        )

    return JSONResponse(
        status_code=upstream_resp.status_code,
        content=upstream_resp.json() if upstream_resp.headers.get("content-type", "").startswith("application/json") else {"raw": upstream_resp.text},
    )
