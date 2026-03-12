"""Integration tests for the evaluation server."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from openclaw_security.config.schema import (
    EvaluatorConfig,
    PlatformConfig,
    ServerConfig,
)
from openclaw_security.config.loader import build_chain
from openclaw_security.server import app


@pytest.fixture
def client():
    """Create a test client with a minimal config (regex evaluator only)."""
    config = PlatformConfig(
        server=ServerConfig(),
        evaluators=[
            EvaluatorConfig(
                name="test-secrets",
                type="regex",
                stages=["tool.before", "tool.after"],
                rules=[
                    {"label": "AWS Key", "pattern": "AKIA[0-9A-Z]{16}", "action": "redact"},
                    {"label": "rm -rf", "pattern": r"rm\s+-rf\s+/", "action": "block"},
                ],
            ),
        ],
    )

    from openclaw_security import server as srv

    srv._chain = build_chain(config)
    srv._config = config
    srv._audit = None
    srv._webhook = None

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

    # Reset global state so tests don't leak
    srv._chain = None
    srv._config = None


# ── Health endpoint ─────────────────────────────────────────────


class TestHealth:
    def test_health_returns_ok(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["evaluators"] == 1


# ── Evaluate endpoint — block ──────────────────────────────────


class TestEvaluateBlock:
    def test_dangerous_command_blocked(self, client: TestClient):
        resp = client.post(
            "/evaluate",
            json={
                "stage": "tool.before",
                "session_id": "s1",
                "tool_name": "exec",
                "tool_args": {"command": "rm -rf /"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "block"
        assert data["blocked"] is True
        assert any("rm -rf" in r for r in data["reasons"])


# ── Evaluate endpoint — redact ─────────────────────────────────


class TestEvaluateRedact:
    def test_aws_key_redacted(self, client: TestClient):
        resp = client.post(
            "/evaluate",
            json={
                "stage": "tool.after",
                "session_id": "s1",
                "tool_name": "exec",
                "tool_result": "Access key: AKIAIOSFODNN7EXAMPLE",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "redact"
        assert data["redacted"] is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in data["redacted"]


# ── Evaluate endpoint — allow ──────────────────────────────────


class TestEvaluateAllow:
    def test_safe_command_allowed(self, client: TestClient):
        resp = client.post(
            "/evaluate",
            json={
                "stage": "tool.before",
                "session_id": "s1",
                "tool_name": "exec",
                "tool_args": {"command": "echo hello"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "allow"
        assert data["blocked"] is False

    def test_safe_output_allowed(self, client: TestClient):
        resp = client.post(
            "/evaluate",
            json={
                "stage": "tool.after",
                "session_id": "s1",
                "tool_name": "exec",
                "tool_result": "Build succeeded. 42 tests passed.",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "allow"


# ── Response shape ──────────────────────────────────────────────


class TestResponseShape:
    def test_response_has_required_fields(self, client: TestClient):
        resp = client.post(
            "/evaluate",
            json={"stage": "tool.before", "session_id": "s1", "tool_name": "exec"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "action" in data
        assert "blocked" in data
        assert "reasons" in data
        assert "results" in data
        assert isinstance(data["results"], list)

    def test_results_contain_evaluator_details(self, client: TestClient):
        resp = client.post(
            "/evaluate",
            json={
                "stage": "tool.before",
                "session_id": "s1",
                "tool_name": "exec",
                "tool_args": {"command": "rm -rf /"},
            },
        )
        data = resp.json()
        assert len(data["results"]) > 0
        result = data["results"][0]
        assert "evaluator" in result
        assert "action" in result
        assert "confidence" in result


# ── Invalid requests ────────────────────────────────────────────


class TestInvalidRequests:
    def test_missing_stage_returns_422(self, client: TestClient):
        resp = client.post("/evaluate", json={"session_id": "s1"})
        assert resp.status_code == 422

    def test_invalid_stage_returns_422(self, client: TestClient):
        resp = client.post(
            "/evaluate",
            json={"stage": "not.a.real.stage", "session_id": "s1"},
        )
        assert resp.status_code == 422

    def test_empty_body_returns_422(self, client: TestClient):
        resp = client.post("/evaluate", content=b"", headers={"Content-Type": "application/json"})
        assert resp.status_code == 422


# ── Multiple evaluators ─────────────────────────────────────────


class TestMultipleEvaluators:
    def test_chain_with_multiple_evaluator_types(self):
        """Verify the server can load regex + sql evaluators together."""
        config = PlatformConfig(
            evaluators=[
                EvaluatorConfig(
                    name="regex-guard",
                    type="regex",
                    stages=["tool.before"],
                    rules=[{"label": "test", "pattern": "dangerous", "action": "block"}],
                ),
                EvaluatorConfig(
                    name="rate-limiter",
                    type="sql",
                    stages=["tool.after"],
                    rules=[
                        {
                            "label": "burst",
                            "query": "SELECT COUNT(*) as cnt FROM events",
                            "condition": "cnt > 100",
                            "action": "block",
                        }
                    ],
                ),
            ]
        )
        chain = build_chain(config)
        assert len(chain) == 2
