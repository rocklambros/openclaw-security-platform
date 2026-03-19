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
  └── TS shim plugin (registers hooks)
        └── HTTP / Unix socket
              └── Python evaluation server
                    ├── Regex     (~μs)   — pattern matching
                    ├── Sigma     (~ms)   — structured threat detection
                    ├── CEL       (~ms)   — conditional policy rules
                    ├── SQL       (~10ms) — temporal / aggregate analysis
                    ├── ML        (~50ms) — local ONNX model inference
                    └── LLM       (~500ms)— semantic LLM-as-judge
```

Each event is forwarded to the Python evaluation server, which runs your configured evaluator chain **cheapest-first**. A `block` result short-circuits — expensive evaluators are skipped.

## Deployment modes

There are two ways to deploy the security platform, depending on what level of control you need.

### Mode 1: Shim plugin (default)

The TS shim registers three OpenClaw hooks that forward events to the evaluation server:

| Hook | Capability | What it covers |
|---|---|---|
| `tool.before` | **Block, redact, warn** | Tool calls before execution — dangerous commands, policy violations |
| `message.before` | Detect and alert | Inbound user messages — prompt injection, abuse |
| `tool.after` | Detect and alert | Tool results — secret leakage, PII, sensitive data |

> **Note:** Only `tool.before` can block actions in shim mode. The `message.before` and `tool.after` hooks are fire-and-forget in OpenClaw's architecture — the platform evaluates them and logs/alerts, but cannot prevent the event from proceeding.

**When to use:** You want lightweight, low-latency security with blocking on tool execution.

### Mode 2: API proxy (full blocking)

A reverse proxy sits between OpenClaw and the Anthropic API. It intercepts every request and response, evaluates at all three stages, and can **block at every stage** — including rewriting the LLM's streaming response to remove blocked tool calls.

```
OpenClaw  ──→  Proxy (:9920)  ──→  Anthropic API
                 │
                 ├── message.before: scan user messages → can block
                 ├── tool.before:    scan tool_use blocks in LLM response → can block
                 └── tool.after:     scan tool results in follow-up requests → can block
```

**When to use:** You need full blocking at every stage, or you want to inspect/modify LLM responses before they reach OpenClaw.

## Quick start

### 1. Install

```bash
git clone https://github.com/zenitysec/openclaw-security-platform.git
cd openclaw-security-platform
pip install -e .
```

### 2. Configure evaluators

```bash
cp config.yaml openclaw-security.yaml
# Edit openclaw-security.yaml — enable/disable evaluators, add rules
```

### 3a. Shim mode setup

Install the plugin into OpenClaw and enable it:

```bash
# Install (link to avoid copying files)
openclaw plugins install --link ./shim

# Enable the plugin
openclaw plugins enable openclaw-security

# Add to your OpenClaw allow-list (required for non-bundled plugins)
openclaw config set plugins.allow '["openclaw-security"]'
```

Start the evaluation server:

```bash
openclaw-security server --config openclaw-security.yaml

# Or with a Unix socket (lower latency):
openclaw-security server --config openclaw-security.yaml --socket /tmp/openclaw-security.sock
```

Restart the OpenClaw gateway so it loads the plugin:

```bash
openclaw gateway --force
```

The shim reads `OPENCLAW_SECURITY_URL` to find the evaluation server (defaults to `http://127.0.0.1:9920/evaluate`). You can override the URL and timeout:

```bash
export OPENCLAW_SECURITY_URL=http://127.0.0.1:9920/evaluate
export OPENCLAW_SECURITY_TIMEOUT=3000
```

Verify the plugin loaded:

```bash
openclaw plugins list
# openclaw-security should show status: loaded
```

### 3b. Proxy mode setup

Configure OpenClaw to route through the proxy:

```bash
# Registers a custom "anthropic-secured" provider, sets it as default model,
# copies your existing Anthropic API key, and disables the shim plugin
openclaw-security setup-openclaw

# Optional: specify a different model or proxy address
openclaw-security setup-openclaw --model claude-sonnet-4-20250514 --port 9920
```

Start the proxy server:

```bash
openclaw-security serve --mode proxy --config openclaw-security.yaml
```

To revert OpenClaw back to using Anthropic directly:

```bash
openclaw-security revert-openclaw
```

No plugin installation needed — the proxy is transparent to OpenClaw.

### 4. Verify

```bash
curl http://127.0.0.1:9920/health
# {"status": "ok", "mode": "server", "evaluators": 5}
```

## Evaluator types

### Regex — fast pattern matching
Compiled regex patterns scanned against event text fields. Catches known secrets (AWS keys, GitHub tokens), PII (SSN, credit cards), and dangerous commands (`rm -rf /`, `DROP TABLE`).

Supports compound rules with `match: all` (AND), `negate: true` (NOT), and per-pattern `field` targeting (different patterns checked against different event fields):

```yaml
- name: secrets-scanner
  type: regex
  stages: [tool.before, tool.after]
  rules:
    # Simple pattern:
    - label: AWS Access Key
      pattern: "AKIA[0-9A-Z]{16}"
      action: redact

    # Compound with per-pattern fields (AND across different fields):
    - label: API key outside safe path
      patterns:
        - pattern: "(?i)api[_-]?key\\s*[:=]"
          field: tool_args.content
        - pattern: "^/safe/"
          field: tool_args.file_path
          negate: true
      match: all
      action: block
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
  stages: [tool.before]
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
  action: warn
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

## Configuration

Configuration can live in a single YAML file, a directory of per-evaluator files, or both. See [`config.yaml`](config.yaml) for a fully commented example.

### Single file

All evaluators inline in one config:

```yaml
server:
  host: 127.0.0.1
  port: 9920

reporting:
  log_file: ./logs/audit.jsonl
  webhook_url: null
  webhook_events: [block, redact]

evaluators:
  - name: my-evaluator
    type: regex | sigma | cel | sql | ml | llm
    enabled: true
    stages: [message.before, tool.before, tool.after]
    # ... type-specific config
```

### Multi-file (evaluators directory)

Split evaluators into individual files for cleaner ownership and easier git diffs. Place YAML files in an `evaluators/` directory next to your config:

```
openclaw-security.yaml          # server + reporting config
evaluators/
  secret-scanner.yaml           # one evaluator per file
  dangerous-commands.yaml
  sigma-threats.yaml
  prompt-injection.yaml
  policy-judge.yaml
```

Each file is a single evaluator config (no wrapper list needed):

```yaml
# evaluators/secret-scanner.yaml
name: secret-scanner
type: regex
stages: [tool.before, tool.after]
rules:
  - label: AWS Access Key
    pattern: "AKIA[0-9A-Z]{16}"
    action: redact
```

The loader auto-discovers `evaluators/*.yaml` and `evaluators/*.yml` in alphabetical order. To use a custom directory, set `evaluators_dir` in your main config:

```yaml
evaluators_dir: ./my-rules/
```

### Inline + directory (merged)

You can use both — inline evaluators run first, directory evaluators are appended. If the same `name` appears in both, the directory version wins. This lets teams override shared defaults with project-specific configs.

## Evaluation chain

Evaluators run in cost order with short-circuit on block:

```
Regex ──allow──→ Sigma ──allow──→ CEL ──allow──→ SQL ──allow──→ ML ──allow──→ LLM → allow
  │                │                │               │              │              │
  block            block            block           block          block          warn
  ↓                ↓                ↓               ↓              ↓              ↓
  STOP             STOP             STOP            STOP           STOP        log + continue
```

Actions by priority: **block** > **redact** > **warn** > **allow**.

## CLI

```
openclaw-security server  --config <path>  [--host HOST] [--port PORT] [--socket PATH]
openclaw-security proxy   --config <path>  [--host HOST] [--port PORT]
```

The `server` subcommand starts the evaluation endpoint for shim mode. The `proxy` subcommand starts the Anthropic API reverse proxy with inline evaluation.

Both modes serve the dashboard at `/dashboard` and the health endpoint at `/health`.

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
{ "status": "ok", "mode": "server", "evaluators": 5 }
```

## Project structure

```
├── pyproject.toml
├── config.yaml                        # Example configuration (all evaluator types)
├── demo-config.yaml                   # Demo configuration (regex + sigma + CEL)
├── e2e-config.yaml                    # Thorough E2E test config (all evaluator types)
├── evaluators/                        # Drop-in per-evaluator configs (auto-discovered)
│   ├── secret-scanner.yaml
│   └── ...
├── openclaw_security/
│   ├── cli.py                         # CLI entrypoint (server/proxy subcommands)
│   ├── server.py                      # FastAPI evaluation server + proxy bootstrap
│   ├── proxy.py                       # Anthropic API reverse proxy (SSE streaming)
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
├── rules/                             # Default rule packs
│   └── sigma/dangerous-tools.yaml
└── scripts/
    └── gen-demo-model.py              # Generate demo ONNX model for ML evaluator
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
