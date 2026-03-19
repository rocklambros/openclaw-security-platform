/**
 * OpenClaw Security Platform — TS shim plugin.
 *
 * This thin plugin registers OpenClaw lifecycle hooks and forwards every event
 * to the Python evaluation server over HTTP. The Python side runs the evaluator
 * chain and returns a verdict.
 *
 * Hooks used:
 *   - before_tool_call  (sequential, can block or modify params)
 *   - after_tool_call   (fire-and-forget, for logging/alerting)
 *   - message_received  (fire-and-forget, for inbound message scanning)
 */

const DEFAULT_URL = "http://127.0.0.1:9920/evaluate";

interface Verdict {
  action: "allow" | "block" | "detect" | "redact";
  blocked: boolean;
  reasons: string[];
  redacted?: string;
}

async function forward(event: Record<string, unknown>): Promise<Verdict> {
  const url = process.env.OPENCLAW_SECURITY_URL || DEFAULT_URL;
  const timeout = parseInt(process.env.OPENCLAW_SECURITY_TIMEOUT || "3000", 10);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
      signal: controller.signal,
    });
    if (!resp.ok) {
      console.error(`[openclaw-security] Server returned ${resp.status}`);
      return { action: "allow", blocked: false, reasons: [] };
    }
    return (await resp.json()) as Verdict;
  } catch (err: any) {
    if (err.name === "AbortError") {
      console.warn("[openclaw-security] Evaluation timed out — defaulting to allow");
    } else {
      console.error("[openclaw-security] Failed to reach evaluation server:", err.message);
    }
    return { action: "allow", blocked: false, reasons: [] };
  } finally {
    clearTimeout(timer);
  }
}

export default function register(api: any) {
  const PRIORITY = 1000; // Run early in the hook chain

  // ── before_tool_call ─────────────────────────────────────────
  // Sequential hook: can return { block, blockReason } or { params } to modify.
  api.on(
    "before_tool_call",
    async (event: any, _ctx: any) => {
      const verdict = await forward({
        stage: "tool.before",
        session_id: _ctx?.sessionKey || _ctx?.sessionId || "",
        tool_name: event.toolName || "",
        tool_args: event.params || {},
        timestamp: Date.now() / 1000,
      });

      if (verdict.blocked) {
        return {
          block: true,
          blockReason: verdict.reasons.join("; ") || "Blocked by security policy",
        };
      }

      // If the verdict modified params (future use), pass them through
      return {};
    },
    { priority: PRIORITY },
  );

  // ── after_tool_call ──────────────────────────────────────────
  // Fire-and-forget: inspect tool results for secrets/sensitive data.
  api.on(
    "after_tool_call",
    async (event: any, _ctx: any) => {
      const verdict = await forward({
        stage: "tool.after",
        session_id: _ctx?.sessionKey || _ctx?.sessionId || "",
        tool_name: event.toolName || "",
        tool_args: event.params || {},
        tool_result: typeof event.result === "string" ? event.result : JSON.stringify(event.result),
        timestamp: Date.now() / 1000,
      });

      if (verdict.action !== "allow") {
        const tag = verdict.action === "block" ? "BLOCKED" : verdict.action.toUpperCase();
        console.warn(
          `[openclaw-security] after_tool_call: ${tag} — ${verdict.reasons.join("; ")}`,
        );
      }
    },
    { priority: PRIORITY },
  );

  // ── message_received ─────────────────────────────────────────
  // Fire-and-forget: scan inbound messages for prompt injection / PII.
  api.on(
    "message_received",
    async (event: any, _ctx: any) => {
      const verdict = await forward({
        stage: "message.before",
        session_id: _ctx?.sessionKey || _ctx?.sessionId || "",
        message_text: event.text || event.content || "",
        channel: event.channel || "",
        user_id: event.userId || event.peerId || "",
        timestamp: Date.now() / 1000,
      });

      if (verdict.action !== "allow") {
        const tag = verdict.action === "block" ? "BLOCKED" : verdict.action.toUpperCase();
        console.warn(
          `[openclaw-security] message_received: ${tag} — ${verdict.reasons.join("; ")}`,
        );
      }
    },
    { priority: PRIORITY },
  );

  console.log("[openclaw-security] Security hooks registered (before_tool_call, after_tool_call, message_received)");
}
