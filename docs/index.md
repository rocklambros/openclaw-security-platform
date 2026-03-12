---
layout: default
title: OpenClaw Security Platform
---

<div class="hero">
  <div class="hero-badge">
    <span class="dot"></span>
    Open Source Security Infrastructure
  </div>
  <h1>
    Security for<br><span class="accent">OpenClaw Agents</span>
  </h1>
  <p class="subtitle">
    Plug in your own evaluators — regex, Sigma, CEL, SQL, ML, or LLM-as-judge —
    and protect your AI agents in minutes. Bring-your-own-security.
  </p>
  <div class="hero-buttons">
    <a href="https://github.com/zenitysec/openclaw-security-platform" class="btn btn-primary">View on GitHub</a>
    <a href="#quick-start" class="btn btn-secondary">Quick Start</a>
  </div>
</div>

<section id="why">
  <div class="container">
    <div class="section-label">Why</div>
    <h2>Guard every stage of the agent lifecycle</h2>
    <p class="section-desc">
      OpenClaw gives you hooks into the agent loop. This platform turns those hooks
      into a full security pipeline.
    </p>

    <table class="stage-table">
      <thead>
        <tr><th>Stage</th><th>What it guards</th></tr>
      </thead>
      <tbody>
        <tr><td>message.before</td><td>Inbound prompts — injection, PII, abuse</td></tr>
        <tr><td>tool.before</td><td>Tool calls — dangerous commands, policy violations</td></tr>
        <tr><td>tool.after</td><td>Tool output — secret leakage, sensitive data</td></tr>
      </tbody>
    </table>

    <div class="chain-flow">
      <div class="chain-step">regex <span class="time">~1 μs</span></div>
      <span class="chain-arrow">&rarr;</span>
      <div class="chain-step">sigma <span class="time">~1 ms</span></div>
      <span class="chain-arrow">&rarr;</span>
      <div class="chain-step">CEL <span class="time">~1 ms</span></div>
      <span class="chain-arrow">&rarr;</span>
      <div class="chain-step">SQL <span class="time">~10 ms</span></div>
      <span class="chain-arrow">&rarr;</span>
      <div class="chain-step">ML <span class="time">~50 ms</span></div>
      <span class="chain-arrow">&rarr;</span>
      <div class="chain-step">LLM <span class="time">~500 ms</span></div>
    </div>
    <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.75rem;">
      Cheapest evaluators run first. Short-circuits on block — if regex catches it, ML never wakes up.
    </p>
  </div>
</section>

<section id="evaluators">
  <div class="container">
    <div class="section-label">Evaluators</div>
    <h2>Six tiers of defense</h2>
    <p class="section-desc">
      From microsecond pattern matching to semantic AI judgement.
      Use what you need, skip what you don't.
    </p>

    <div class="cards">
      <div class="card">
        <div class="card-type">regex</div>
        <h3>Pattern Matching</h3>
        <p>Microsecond-fast secret scanning and command detection. Ships with rules for AWS keys, GitHub tokens, PII, and dangerous commands.</p>
<pre>- label: AWS Access Key
  pattern: "AKIA[0-9A-Z]{16}"
  action: redact</pre>
      </div>

      <div class="card">
        <div class="card-type">sigma</div>
        <h3>Threat Detection</h3>
        <p>Industry-standard YAML detection rules mapped to OpenClaw events. Reuse rules from the entire Sigma ecosystem.</p>
<pre>title: Dangerous file write
detection:
  selection:
    tool_name: write_file
    tool_args.path|contains: '/etc/'
  condition: selection
level: high</pre>
      </div>

      <div class="card">
        <div class="card-type">cel</div>
        <h3>Policy Rules</h3>
        <p>Common Expression Language for conditional policies. Full access to every event field with boolean logic.</p>
<pre>- label: block-rm-rf
  expr: >
    tool_name == "exec" &&
    tool_args_command.matches("rm\\s+-r")
  action: block</pre>
      </div>

      <div class="card">
        <div class="card-type">sql</div>
        <h3>Aggregate Analytics</h3>
        <p>In-memory SQLite for temporal queries — rate limiting, burst detection, session-level anomaly scoring.</p>
<pre>- label: exec-burst
  query: >
    SELECT COUNT(*) as cnt FROM events
    WHERE tool_name = 'exec'
    AND timestamp > :now - 60
  condition: "cnt > 20"
  action: block</pre>
      </div>

      <div class="card">
        <div class="card-type">ml</div>
        <h3>Local Model Inference</h3>
        <p>ONNX Runtime models for prompt injection, toxicity, and custom classifiers. Runs locally — no API calls, no data leaves your machine.</p>
<pre>- name: prompt-injection-detector
  type: ml
  model_path: ./models/pi-v3.onnx
  threshold: 0.85
  action: block</pre>
      </div>

      <div class="card">
        <div class="card-type">llm</div>
        <h3>Semantic Evaluation</h3>
        <p>Use Claude as a judge for nuanced decisions that rules can't capture. Policy-driven, structured verdicts.</p>
<pre>- name: semantic-guard
  type: llm
  model: claude-haiku-4-5-20251001
  policy: |
    Does the output contain
    sensitive information?
  default_action: warn</pre>
      </div>
    </div>
  </div>
</section>

<section id="architecture">
  <div class="container">
    <div class="section-label">Architecture</div>
    <h2>Thin shim, heavy Python</h2>
    <p class="section-desc">
      A ~130-line TypeScript plugin forwards OpenClaw hook events to a Python evaluation server over HTTP.
    </p>

    <div class="arch-box">
<pre>
 OpenClaw Gateway                    Python Evaluation Server
 ─────────────────                   ─────────────────────────

 before_tool_call ──┐               ┌──────────────────────────┐
 after_tool_call  ──┼── HTTP POST ──▶  Evaluator Chain          │
 message_received ──┘   /evaluate   │                          │
                                    │  regex → sigma → CEL     │
                                    │  → SQL → ML → LLM       │
              ◀─────────────────────┤                          │
              { action, blocked,    │  Short-circuits on BLOCK │
                reasons, redacted } │  block > redact > warn   │
                                    └──────────────────────────┘
</pre>
    </div>
  </div>
</section>

<section id="quick-start">
  <div class="container">
    <div class="section-label">Get Started</div>
    <h2>Running in four steps</h2>

    <div class="steps">
      <div class="step">
        <div class="step-num">1</div>
        <div class="step-content">
          <h3>Install the platform</h3>
          <p><code>pip install -e .</code></p>
        </div>
      </div>
      <div class="step">
        <div class="step-num">2</div>
        <div class="step-content">
          <h3>Start the evaluation server</h3>
          <p><code>openclaw-security</code> — runs on <code>http://127.0.0.1:9920</code></p>
        </div>
      </div>
      <div class="step">
        <div class="step-num">3</div>
        <div class="step-content">
          <h3>Link the OpenClaw plugin</h3>
          <p><code>cd shim && openclaw plugins install --link .</code></p>
        </div>
      </div>
      <div class="step">
        <div class="step-num">4</div>
        <div class="step-content">
          <h3>Restart your gateway</h3>
          <p><code>openclaw gateway restart</code> — hooks are live.</p>
        </div>
      </div>
    </div>
  </div>
</section>

<section id="api">
  <div class="container">
    <div class="section-label">API</div>
    <h2>Two endpoints, zero complexity</h2>

    <div class="cards" style="grid-template-columns: 1fr 1fr;">
      <div class="card">
        <div class="card-type">POST /evaluate</div>
        <h3>Evaluate an event</h3>
<pre>{
  "stage": "tool.before",
  "session_id": "sess-abc",
  "tool_name": "exec",
  "tool_args": { "command": "rm -rf /" }
}

→ { "action": "block",
    "blocked": true,
    "reasons": ["Recursive delete root"] }</pre>
      </div>

      <div class="card">
        <div class="card-type">GET /health</div>
        <h3>Health check</h3>
<pre>{
  "status": "ok",
  "evaluators": 4
}</pre>
        <p style="margin-top: 1rem;">Returns evaluator count and server status. Use for monitoring and liveness probes.</p>
      </div>
    </div>
  </div>
</section>

<section id="extend">
  <div class="container">
    <div class="section-label">Extend</div>
    <h2>Build your own evaluator</h2>
    <p class="section-desc">
      Subclass <code>Evaluator</code>, implement <code>evaluate()</code>, register it. That's it.
    </p>

<pre>from openclaw_security.evaluators.base import Evaluator
from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import EvalResult, Action

class MyEvaluator(Evaluator):
    eval_type = "custom"

    async def evaluate(self, ctx: EvalContext) -> EvalResult:
        if "bad" in ctx.searchable_text():
            return self._result(Action.BLOCK, 1.0, "Blocked")
        return self._result(Action.ALLOW, 0.0, "Clean")</pre>

    <p style="color: var(--text-secondary); margin-top: 1rem;">
      Register in <code>openclaw_security/evaluators/__init__.py</code> and it joins the chain automatically.
    </p>
  </div>
</section>

<section id="testing">
  <div class="container">
    <div class="section-label">Testing</div>
    <h2>101 tests, all green</h2>
    <p class="section-desc">
      Unit tests for every evaluator type, chain behavior, and server endpoint.
      Integration tests spin up the real eval server and OpenClaw gateway.
    </p>

<pre># Unit tests (~4s)
pytest tests/ --ignore=tests/test_integration.py

# Integration tests (eval server + HTTP pipeline)
pytest tests/test_integration.py -m "not slow"

# Full gateway integration
pytest tests/test_integration.py -m slow

# Everything
pytest tests/</pre>
  </div>
</section>

<footer>
  <div class="container">
    <p>
      Built by <a href="https://github.com/zenitysec">Zenity Security</a>
      &nbsp;&middot;&nbsp;
      <a href="https://github.com/zenitysec/openclaw-security-platform">GitHub</a>
      &nbsp;&middot;&nbsp;
      <a href="https://openclaw.ai">OpenClaw</a>
    </p>
  </div>
</footer>
