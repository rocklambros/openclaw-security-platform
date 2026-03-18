# OpenClaw Security Platform

**Bring-your-own-security for OpenClaw.**

OpenClaw gives your AI agent access to messaging platforms, shell commands, file systems, and APIs — but ships with no security layer. This project fills that gap: it's a security infrastructure layer that plugs into any existing OpenClaw deployment and lets you decide how to protect it.

You pick the evaluators. You write the rules. You control the policies. We provide the wiring.

- **Already running OpenClaw?** Drop this in. No fork, no migration — it's a plugin.
- **Have your own detection models?** Plug them in as ONNX models or LLM-as-judge policies.
- **Want to reuse your SOC's Sigma rules?** Point them at OpenClaw events.
- **Need custom policies?** Write them in regex, CEL, SQL, or Python — your choice.

The platform doesn't tell you what's dangerous. **You** tell **it** — through whatever combination of evaluators fits your threat model.

## How it works

```
OpenClaw Gateway
  └── TS shim plugin (registers interceptors)
        └── HTTP / Unix socket
              └── Python evaluation server
                    ├── Regex     (~μs)   — pattern matching
                    ├── Sigma     (~ms)   — structured threat detection
                    ├── CEL       (~ms)   — conditional policy rules
                    ├── SQL       (~10ms) — temporal / aggregate analysis
                    ├── ML        (~50ms) — local ONNX model inference
                    └── LLM       (~500ms)— semantic LLM-as-judge
```

The TS shim registers four OpenClaw interceptors:

| Interceptor | What it guards |
|---|---|
| `message.before` | Inbound user messages (prompt injection, abuse) |
| `tool.before` | Tool calls before execution (dangerous commands, policy violations) |
| `tool.after` | Tool results before they reach the agent (secrets, PII, data leaks) |
| `params.before` | LLM parameters before the API call |

Each event is forwarded to the Python evaluation server, which runs your configured evaluator chain **cheapest-first**. A `block` at any stage short-circuits — expensive evaluators are skipped.

## Evaluator types

### Regex — fast pattern matching
Compiled regex patterns scanned against event text fields. Catches known secrets (AWS keys, GitHub tokens), PII (SSN, credit cards), and dangerous commands (`rm -rf /`, `DROP TABLE`).

```yaml
- name: secrets-scanner
  type: regex
  stages: [tool.before, tool.after]
  rules:
    - label: AWS Access Key
      pattern: "AKIA[0-9A-Z]{16}"
      action: redact
    - label: Destructive rm
      pattern: "rm\\s+-rf\\s+/"
      action: block
      fields: [tool_args.command]
```

### Sigma — structured threat detection
Industry-standard [Sigma rules](https://sigmahq.io/) mapped to OpenClaw events. Write detection logic once in YAML, share it across your SOC team.

```yaml
title: Shell command with network exfiltration indicators
logsource:
  product: openclaw
  service: tool
detection:
  selection:
    tool_name: exec
  network_tools:
    tool_args.command|contains: [curl, wget, nc, netcat]
  data_pipes:
    tool_args.command|contains: ["|", ">", base64]
  condition: selection and network_tools and data_pipes
level: critical
```

### CEL — conditional policy rules
[Common Expression Language](https://github.com/google/cel-spec) for complex conditional logic that regex can't express.

```yaml
- name: access-policies
  type: cel
  stages: [tool.before]
  rules:
    - label: block-exec-non-admin
      expr: 'tool_name == "exec" && user_id != "admin"'
      action: warn
      reason: Shell execution by non-admin user
```

### SQL — temporal / aggregate analysis
In-memory SQLite stores recent events. SQL queries detect patterns across multiple events — rate limiting, bursts, session anomalies.

```yaml
- name: rate-limiter
  type: sql
  stages: [tool.before, tool.after]
  rules:
    - label: exec-burst
      query: >
        SELECT COUNT(*) as cnt FROM events
        WHERE tool_name = 'exec' AND session_id = :session_id
        AND timestamp > :now - 60
      condition: "cnt > 20"
      action: block
      reason: "Too many tool executions in 60 seconds"
```

### ML — local model inference
ONNX Runtime for fast local classification — prompt injection detection, anomaly detection, toxicity. No external API calls.

```yaml
- name: prompt-injection-detector
  type: ml
  stages: [message.before]
  model_path: ./models/prompt-injection-v3.onnx
  threshold: 0.85
  action: block
  label: prompt_injection
```

### LLM — semantic evaluation
Claude (or any Anthropic model) as a judge for nuanced security decisions that rules can't capture. Best used on `tool.after` where latency is more acceptable.

```yaml
- name: semantic-guard
  type: llm
  stages: [tool.after]
  provider: anthropic
  model: claude-haiku-4-5-20251001
  policy: |
    Evaluate whether the tool output contains sensitive information
    that should not leave the user's session.
  default_action: warn
```

## Quick start

### 1. Install the Python evaluation server

```bash
cd OpenClawSecurityPlatform
pip install -e .
```

### 2. Configure your evaluators

```bash
cp config.yaml openclaw-security.yaml
# Edit openclaw-security.yaml — enable/disable evaluators, add rules
```

### 3. Start the server

```bash
openclaw-security --config openclaw-security.yaml

# Or with a Unix socket (lower latency):
openclaw-security --config openclaw-security.yaml --socket /tmp/openclaw-security.sock
```

### 4. Install the OpenClaw plugin

Copy the `shim/` directory into your OpenClaw plugins folder, or register it in your OpenClaw config:

```bash
# Point the shim at your running server
export OPENCLAW_SECURITY_URL=http://127.0.0.1:9920/evaluate
```

### 5. Verify

```bash
curl http://127.0.0.1:9920/health
# {"status": "ok", "evaluators": 5}
```

## Configuration

The full configuration lives in a single YAML file. See [`config.yaml`](config.yaml) for a fully commented example.

```yaml
server:
  host: 127.0.0.1
  port: 9920
  unix_socket: null              # set to prefer unix socket

reporting:
  log_file: ./logs/audit.jsonl   # JSON-lines audit trail
  webhook_url: null              # POST verdicts to SIEM / Slack
  webhook_events: [block, redact]

evaluators:
  - name: my-evaluator
    type: regex | sigma | cel | sql | ml | llm
    enabled: true
    stages: [message.before, tool.before, tool.after, params.before]
    # ... type-specific config
```

## Evaluation chain

Evaluators run in cost order with short-circuit on block:

```
Regex ──allow──→ Sigma ──allow──→ CEL ──allow──→ SQL ──allow──→ ML ──allow──→ LLM → ✅
  │                │                │               │              │              │
  block            block            block           block          block          warn
  ↓                ↓                ↓               ↓              ↓              ↓
  🚫               🚫               🚫              🚫             🚫          ⚠️ log
```

Actions by priority: **block** > **redact** > **warn** > **allow**.

## Reporting

- **Audit log** — append-only JSON-lines file with every evaluation result, timing, and metadata
- **Webhook** — POST blocked/redacted events to an external endpoint (SIEM, Slack, PagerDuty)

## Dashboard

A built-in real-time dashboard is available at `http://127.0.0.1:9920/dashboard` when the server is running. No extra setup required.

- **Live event stream** — every evaluation (block, redact, warn, allow) appears instantly via Server-Sent Events
- **Stats** — running totals for each action type, updated live
- **History** — in-memory ring buffer of the last 10,000 events with per-evaluation latency
- **Filters** — filter by action, stage, or free-text search; click any event for full evaluator details
- **API** — programmatic access at `/dashboard/api/history` and `/dashboard/api/stats`

## API

### `POST /evaluate`

```json
{
  "stage": "tool.before",
  "session_id": "abc-123",
  "user_id": "user@example.com",
  "tool_name": "exec",
  "tool_args": { "command": "rm -rf /" }
}
```

Response:

```json
{
  "action": "block",
  "blocked": true,
  "reasons": ["Regex match: Recursive delete root"],
  "redacted": null,
  "results": [
    {
      "evaluator": "dangerous-commands",
      "action": "block",
      "confidence": 1.0,
      "reason": "Regex match: Recursive delete root"
    }
  ]
}
```

### `GET /health`

```json
{ "status": "ok", "evaluators": 5 }
```

## Project structure

```
├── pyproject.toml
├── config.yaml                        # Example configuration
├── openclaw_security/
│   ├── server.py                      # FastAPI evaluation server
│   ├── engine/
│   │   ├── context.py                 # Normalized event model
│   │   ├── result.py                  # Result types + aggregation
│   │   └── chain.py                   # Ordered evaluator chain runner
│   ├── evaluators/
│   │   ├── base.py                    # Abstract evaluator interface
│   │   ├── regex_eval.py
│   │   ├── sigma_eval.py
│   │   ├── cel_eval.py
│   │   ├── sql_eval.py
│   │   ├── ml_eval.py
│   │   └── llm_eval.py
│   ├── config/
│   │   ├── schema.py                  # Pydantic config validation
│   │   └── loader.py                  # YAML → EvaluatorChain builder
│   └── reporting/
│       ├── logger.py                  # JSON-lines audit log
│       └── webhook.py                 # External webhook reporter
├── shim/
│   └── src/index.ts                   # Thin TS OpenClaw plugin
└── rules/                             # Default rule packs
    ├── regex/secrets.yaml
    ├── sigma/dangerous-tools.yaml
    └── cel/policies.yaml
```

## Writing custom evaluators

The whole point of this platform is that **you** bring the security logic. The six built-in evaluator types cover common patterns, but if they don't fit — write your own in a few lines of Python.

Subclass `Evaluator` and implement `evaluate`:

```python
from openclaw_security.evaluators.base import Evaluator
from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import EvalResult, Action

class MyEvaluator(Evaluator):
    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        if "bad_thing" in ctx.searchable_text():
            return self._result(action=Action.BLOCK, reason="Found bad thing")
        return self._result()
```

Register it in `openclaw_security/evaluators/__init__.py`:

```python
EVALUATOR_REGISTRY["my_type"] = MyEvaluator
```

Then use `type: my_type` in your config.

## License

MIT
