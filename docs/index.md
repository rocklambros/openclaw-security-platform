---
layout: default
title: OpenClaw Security Platform
---

<p align="center">
  <img src="assets/logo.svg" alt="OpenClaw Security" width="120"/>
</p>

# OpenClaw Security Platform

**Bring-your-own-security infrastructure for [OpenClaw](https://openclaw.ai) AI agents.**

Plug in your own evaluators — regex, Sigma rules, CEL policies, SQL analytics, ML models, or LLM-as-judge — and protect your agents in minutes.

---

## Why?

OpenClaw gives you hooks into the agent lifecycle. This platform turns those hooks into a full security pipeline:

| Stage | What it guards |
|---|---|
| `message.before` | Inbound prompts — injection, PII, abuse |
| `tool.before` | Tool calls — dangerous commands, policy violations |
| `tool.after` | Tool output — secret leakage, sensitive data |

Every event flows through a **cost-ordered evaluator chain** that short-circuits on block:

```
regex (~1 μs) → sigma (~1 ms) → CEL (~1 ms) → SQL (~10 ms) → ML (~50 ms) → LLM (~500 ms)
```

Cheap evaluators run first. If a regex catches `rm -rf /`, the ML model never wakes up.

---

## Evaluator Types

### Regex — Pattern Matching
Microsecond-fast secret scanning and command detection. Ships with rules for AWS keys, GitHub tokens, PII, and dangerous shell commands.

```yaml
- label: AWS Access Key
  pattern: "AKIA[0-9A-Z]{16}"
  action: redact
```

### Sigma — Threat Detection
Industry-standard YAML detection rules mapped to OpenClaw events. Write once, detect everywhere.

```yaml
title: Dangerous file write
detection:
  selection:
    tool_name: write_file
    tool_args.path|contains: '/etc/'
  condition: selection
level: high
```

### CEL — Policy Rules
[Common Expression Language](https://github.com/google/cel-spec) for conditional policies. Full access to event fields.

```yaml
- label: block-rm-rf
  expr: 'tool_name == "exec" && tool_args_command.matches("rm\\s+-r")'
  action: block
```

### SQL — Aggregate Analytics
In-memory SQLite for temporal queries — rate limiting, burst detection, session-level analytics.

```yaml
- label: exec-burst
  query: >
    SELECT COUNT(*) as cnt FROM events
    WHERE tool_name = 'exec' AND session_id = :session_id
    AND timestamp > :now - 60
  condition: "cnt > 20"
  action: block
```

### ML — Local Model Inference
ONNX Runtime models for prompt injection detection, toxicity scoring, and custom classifiers. Runs locally, no API calls.

```yaml
- name: prompt-injection-detector
  type: ml
  model_path: ./models/prompt-injection-v3.onnx
  threshold: 0.85
  action: block
```

### LLM — Semantic Evaluation
Use Claude (or any Anthropic model) as a judge for nuanced decisions that rules can't capture.

```yaml
- name: semantic-guard
  type: llm
  model: claude-haiku-4-5-20251001
  policy: |
    Evaluate whether the tool output contains sensitive
    information that should not leave the session.
  default_action: warn
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   OpenClaw Gateway                    │
│                                                       │
│  message.before ─┐                                   │
│  tool.before ────┼──→  TS Shim Plugin (~130 lines)   │
│  tool.after ─────┘         │                         │
│                            │ HTTP POST /evaluate     │
└────────────────────────────┼─────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────┐
│              Python Evaluation Server                 │
│                                                       │
│  ┌─────────────────────────────────────────────┐     │
│  │           Evaluator Chain (ordered)          │     │
│  │                                              │     │
│  │  regex → sigma → CEL → SQL → ML → LLM       │     │
│  │                                              │     │
│  │  Short-circuits on BLOCK                     │     │
│  │  Priority: block > redact > warn > allow     │     │
│  └─────────────────────────────────────────────┘     │
│                                                       │
│  POST /evaluate  →  { action, blocked, reasons }     │
│  GET  /health    →  { status, evaluators }           │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# 1. Install
pip install -e .

# 2. Start the evaluation server
openclaw-security
# → Server running on http://127.0.0.1:9920

# 3. Link the OpenClaw plugin
cd shim && openclaw plugins install --link .

# 4. Restart your gateway
openclaw gateway restart
```

The shim registers `before_tool_call`, `after_tool_call`, and `message_received` hooks that forward events to the Python server.

---

## Configuration

All evaluators are defined in `config.yaml`:

```yaml
server:
  host: 127.0.0.1
  port: 9920

evaluators:
  - name: secrets-scanner
    type: regex
    stages: [tool.before, tool.after]
    rules:
      - label: AWS Access Key
        pattern: "AKIA[0-9A-Z]{16}"
        action: redact

  - name: sigma-threats
    type: sigma
    stages: [tool.before, tool.after]
    rules_dir: ./rules/sigma/

  - name: access-policies
    type: cel
    stages: [tool.before]
    rules:
      - label: block-rm-rf
        expr: 'tool_name == "exec" && tool_args_command.matches("rm\\s+-r")'
        action: block
```

---

## API

### `POST /evaluate`

```json
{
  "stage": "tool.before",
  "session_id": "sess-abc",
  "tool_name": "exec",
  "tool_args": { "command": "rm -rf /" }
}
```

Response:

```json
{
  "action": "block",
  "blocked": true,
  "reasons": ["Recursive delete root matched in secrets-scanner"],
  "results": [
    {
      "evaluator": "secrets-scanner",
      "action": "block",
      "confidence": 1.0,
      "reason": "Recursive delete root"
    }
  ]
}
```

### `GET /health`

```json
{ "status": "ok", "evaluators": 4 }
```

---

## Custom Evaluators

Subclass `Evaluator` and register it:

```python
from openclaw_security.evaluators.base import Evaluator
from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import EvalResult, Action

class MyEvaluator(Evaluator):
    eval_type = "custom"

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        if "bad" in ctx.searchable_text():
            return self._result(Action.BLOCK, 1.0, "Bad content detected")
        return self._result(Action.ALLOW, 0.0, "Clean")
```

Register in `openclaw_security/evaluators/__init__.py`:

```python
EVALUATOR_REGISTRY["custom"] = MyEvaluator
```

---

## Testing

```bash
# Unit tests (89 tests, ~4s)
pytest tests/ --ignore=tests/test_integration.py

# Integration tests (starts eval server, tests HTTP pipeline)
pytest tests/test_integration.py -m "not slow"

# Full gateway integration (requires OpenClaw + Anthropic key)
pytest tests/test_integration.py -m slow

# All tests
pytest tests/
```

---

## Links

- [GitHub Repository](https://github.com/zenitysec/openclaw-security-platform)
- [OpenClaw](https://openclaw.ai)
- [Sigma Rules](https://sigmahq.io)
- [CEL Specification](https://github.com/google/cel-spec)

---

<p align="center">
  <sub>Built by <a href="https://github.com/zenitysec">Zenity Security</a></sub>
</p>
