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

<section id="problem">
  <div class="container">
    <div class="section-label">The Problem</div>
    <h2>OpenClaw has no security layer</h2>
    <p class="section-desc" style="max-width: 720px;">
      OpenClaw gives your AI agent access to messaging platforms, shell commands, file systems, and APIs — but ships with no security layer. This project fills that gap.
    </p>
    <div class="cards" style="grid-template-columns: 1fr 1fr;">
      <div class="card">
        <h3>You pick the evaluators</h3>
        <p>Already running OpenClaw? Drop this in. No fork, no migration — it's a plugin. Have your own detection models? Plug them in as ONNX models or LLM-as-judge policies.</p>
      </div>
      <div class="card">
        <h3>You write the rules</h3>
        <p>Want to reuse your SOC's Sigma rules? Point them at OpenClaw events. Need custom policies? Write them in regex, CEL, SQL, or Python — your choice.</p>
      </div>
    </div>
    <p style="color: var(--text-secondary); font-size: 1.05rem; margin-top: 2rem; max-width: 720px;">
      The platform doesn't tell you what's dangerous. <strong style="color: var(--text-primary);">You</strong> tell <strong style="color: var(--text-primary);">it</strong> — through whatever combination of evaluators fits your threat model.
    </p>
  </div>
</section>

<section id="why">
  <div class="container">
    <div class="section-label">How It Works</div>
    <h2>Evaluate every stage of the agent lifecycle</h2>
    <p class="section-desc">
      OpenClaw gives you hooks into the agent loop. This platform turns those hooks
      into a security pipeline — blocking where possible, detecting everywhere.
    </p>

    <table class="stage-table">
      <thead>
        <tr><th>Stage</th><th>Capability</th><th>What it covers</th></tr>
      </thead>
      <tbody>
        <tr><td>tool.before</td><td><strong>Block, redact, warn</strong></td><td>Tool calls — dangerous commands, policy violations</td></tr>
        <tr><td>message.before</td><td>Detect and alert</td><td>Inbound prompts — injection, PII, abuse</td></tr>
        <tr><td>tool.after</td><td>Detect and alert</td><td>Tool output — secret leakage, sensitive data</td></tr>
      </tbody>
    </table>
    <p style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.75rem;">
      Only <code>tool.before</code> can block in OpenClaw (sequential hook). The other stages are fire-and-forget — they evaluate and alert but cannot prevent the event.
      The standalone SDK wrapper can block at all three stages.
    </p>

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
      </div>

      <div class="card">
        <div class="card-type">sigma</div>
        <h3>Threat Detection</h3>
        <p>Industry-standard YAML detection rules mapped to OpenClaw events. Reuse rules from the entire Sigma ecosystem.</p>
      </div>

      <div class="card">
        <div class="card-type">cel</div>
        <h3>Policy Rules</h3>
        <p>Common Expression Language for conditional policies. Full access to every event field with boolean logic.</p>
      </div>

      <div class="card">
        <div class="card-type">sql</div>
        <h3>Aggregate Analytics</h3>
        <p>In-memory SQLite for temporal queries — rate limiting, burst detection, session-level anomaly scoring.</p>
      </div>

      <div class="card">
        <div class="card-type">ml</div>
        <h3>Local Model Inference</h3>
        <p>ONNX Runtime models for prompt injection, toxicity, and custom classifiers. Runs locally — no API calls, no data leaves your machine.</p>
      </div>

      <div class="card">
        <div class="card-type">llm</div>
        <h3>Semantic Evaluation</h3>
        <p>Use Claude as a judge for nuanced decisions that rules can't capture. Policy-driven, structured verdicts.</p>
      </div>
    </div>

    <p style="color: var(--text-secondary); font-size: 0.95rem; margin-top: 2rem;">
      Every evaluator type is extensible — bring your own rules, models, and policies. See the <a href="https://github.com/zenitysec/openclaw-security-platform">GitHub repo</a> for configuration examples and how to write custom evaluators.
    </p>
  </div>
</section>

<section id="architecture">
  <div class="container">
    <div class="section-label">Architecture</div>
    <h2>Thin shim, heavy Python</h2>
    <p class="section-desc">
      A lightweight TypeScript plugin forwards OpenClaw hook events to a Python evaluation server over HTTP.
    </p>

    <div class="arch-diagram">
      <div class="arch-node arch-node-gateway">
        <div class="arch-node-label">Plugin</div>
        <h3>OpenClaw Gateway</h3>
        <div class="arch-hooks">
          <div class="arch-hook"><span class="arch-hook-dot blue"></span> before_tool_call</div>
          <div class="arch-hook"><span class="arch-hook-dot amber"></span> after_tool_call</div>
          <div class="arch-hook"><span class="arch-hook-dot green"></span> message_received</div>
        </div>
      </div>

      <div class="arch-connector">
        <div class="arch-connector-arrow">HTTP POST<br>/evaluate</div>
      </div>

      <div class="arch-node arch-node-server">
        <div class="arch-node-label">Evaluation Server</div>
        <h3>Evaluator Chain</h3>
        <div class="arch-chain-list">
          <div class="arch-chain-item"><span class="name">regex</span><span class="latency">~1 μs</span></div>
          <div class="arch-chain-item"><span class="name">sigma</span><span class="latency">~1 ms</span></div>
          <div class="arch-chain-item"><span class="name">CEL</span><span class="latency">~1 ms</span></div>
          <div class="arch-chain-item"><span class="name">SQL</span><span class="latency">~10 ms</span></div>
          <div class="arch-chain-item"><span class="name">ML</span><span class="latency">~50 ms</span></div>
          <div class="arch-chain-item"><span class="name">LLM</span><span class="latency">~500 ms</span></div>
        </div>
        <div class="arch-response">
          <span>→</span> { action, blocked, reasons, redacted }<br>
          Short-circuits on <span>BLOCK</span> · block > redact > warn
        </div>
      </div>
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

<section id="dashboard">
  <div class="container">
    <div class="section-label">Visibility</div>
    <h2>Real-time security dashboard</h2>
    <p class="section-desc">
      Every evaluation streams live to a built-in dashboard at <code>/dashboard</code> — no extra setup required.
    </p>

    <div class="cards" style="grid-template-columns: 1fr 1fr;">
      <div class="card">
        <h3>Live event stream</h3>
        <p>Every block, redact, warn, and allow appears instantly via Server-Sent Events. Filter by action, stage, or free-text search. Click any event for full evaluator details.</p>
      </div>
      <div class="card">
        <h3>Stats and history</h3>
        <p>Running totals for every action type. In-memory history of the last 10,000 events with latency tracking per evaluation. All available via API at <code>/dashboard/api/</code>.</p>
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
