"""Dashboard routes — serves UI, SSE stream, and history API."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from openclaw_security.dashboard.store import EventStore

router = APIRouter(prefix="/dashboard")

_TEMPLATE_PATH = Path(__file__).parent / "dashboard.html"


def _get_store(request: Request) -> EventStore:
    return request.app.state.event_store


@router.get("", response_class=HTMLResponse)
async def dashboard_page():
    """Serve the dashboard HTML."""
    html = _TEMPLATE_PATH.read_text()
    return HTMLResponse(html)


@router.get("/api/history")
async def history(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None),
    actions: list[str] | None = Query(None),
    stage: str | None = Query(None),
    start_ts: float | None = Query(None),
    end_ts: float | None = Query(None),
):
    """Return paginated event history with server-side filtering."""
    store = _get_store(request)
    events = store.history(
        limit=limit,
        offset=offset,
        action=action,
        actions=actions,
        stage=stage,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    return {"events": events, "stats": store.stats()}


@router.get("/api/stats")
async def stats(request: Request):
    """Return aggregate statistics."""
    store = _get_store(request)
    return store.stats()


@router.get("/events")
async def event_stream(request: Request):
    """SSE endpoint — streams evaluation events in real time."""
    store = _get_store(request)
    queue = store.subscribe()

    async def generate():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    data = json.dumps(event.to_dict())
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            store.unsubscribe(queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
