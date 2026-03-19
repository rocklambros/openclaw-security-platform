#!/usr/bin/env python3
"""
OpenClaw Security Platform — Interactive Chat Demo

A real Claude-powered agent loop with security checks at every stage:

  1. User types a message        → evaluated at message.before
  2. Claude calls a tool         → evaluated at tool.before
  3. Tool produces output        → evaluated at tool.after
  4. Claude sees result & responds

Usage:
  Terminal 1:  openclaw-security -c demo-chat-config.yaml
  Terminal 2:  python3 demo-chat.py --api-key sk-ant-...

  Or set ANTHROPIC_API_KEY in your environment.

Try messages with the words "red", "yellow", or "green" to trigger
blocks at different stages.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid

import anthropic
import httpx

EVAL_URL = "http://127.0.0.1:9920"
SESSION_ID = f"chat-{uuid.uuid4().hex[:8]}"

# Colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Tools available to the agent
TOOLS = [
    {
        "name": "run_shell",
        "description": "Execute a shell command and return the output. Use this to answer questions that require running commands.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute",
                }
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read the contents of a file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to read",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file. Creates the file if it doesn't exist, overwrites if it does.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to write to",
                },
                "content": {
                    "type": "string",
                    "description": "The content to write to the file",
                },
            },
            "required": ["path", "content"],
        },
    },
]

SYSTEM_PROMPT = (
    "You are a helpful assistant with access to tools. "
    "When the user asks you to do something that requires running a command or reading a file, use the appropriate tool. "
    "Keep your responses concise."
)


def evaluate(stage: str, **kwargs) -> dict:
    """Call the security evaluation server."""
    payload = {"stage": stage, "session_id": SESSION_ID, **kwargs}
    resp = httpx.post(f"{EVAL_URL}/evaluate", json=payload, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


def print_security(icon: str, color: str, label: str, detail: str = "") -> None:
    detail_str = f"  {DIM}{detail}{RESET}" if detail else ""
    print(f"  {color}{icon}{RESET} {DIM}{label}{RESET}{detail_str}")


def print_block(stage: str, reasons: list[str]) -> None:
    label = {
        "message.before": "MESSAGE INTAKE",
        "tool.before": "TOOL CALL",
        "tool.after": "TOOL OUTPUT",
    }.get(stage, stage)
    print(f"\n  {RED}{BOLD}✗ BLOCKED{RESET} at {BOLD}{label}{RESET}")
    for r in reasons:
        print(f"    {DIM}→ {r}{RESET}")


def execute_tool(name: str, args: dict) -> str:
    """Actually execute a tool and return its output."""
    if name == "run_shell":
        try:
            result = subprocess.run(
                args["command"],
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout
            if result.stderr:
                output += result.stderr
            return output.strip() or "(no output)"
        except subprocess.TimeoutExpired:
            return "(command timed out after 10s)"
    elif name == "read_file":
        try:
            with open(args["path"]) as f:
                return f.read()
        except (FileNotFoundError, PermissionError) as e:
            return f"Error: {e}"
    return f"Unknown tool: {name}"


def run_agent_loop(client: anthropic.Anthropic, messages: list[dict]) -> None:
    """Run the agent loop: send to Claude, handle tool use, evaluate at each stage."""

    while True:
        # Call Claude
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        # Process response content blocks
        assistant_content = response.content
        tool_results = []

        for block in assistant_content:
            if block.type == "text" and block.text.strip():
                print(f"\n  {BOLD}agent ➤{RESET} {block.text}")

            elif block.type == "tool_use":
                tool_name = block.name
                tool_input = block.input
                tool_id = block.id

                print(f"\n  {YELLOW}⚙{RESET}  {DIM}Tool call:{RESET} {BOLD}{tool_name}{RESET}({DIM}{json.dumps(tool_input)}{RESET})")

                # --- Security: tool.before ---
                result = evaluate(
                    "tool.before",
                    tool_name=tool_name,
                    tool_args=tool_input,
                )
                if result["blocked"]:
                    print_block("tool.before", result["reasons"])
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": f"SECURITY BLOCK: {'; '.join(result['reasons'])}",
                        "is_error": True,
                    })
                    continue
                print_security("✓", GREEN, "Passed tool.before")

                # Execute the tool
                tool_output = execute_tool(tool_name, tool_input)
                print(f"  {DIM}↳ {tool_output[:200]}{'...' if len(tool_output) > 200 else ''}{RESET}")

                # --- Security: tool.after ---
                result = evaluate(
                    "tool.after",
                    tool_name=tool_name,
                    tool_result=tool_output,
                )
                if result["blocked"]:
                    print_block("tool.after", result["reasons"])
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": f"SECURITY BLOCK: {'; '.join(result['reasons'])}",
                        "is_error": True,
                    })
                    continue
                if result.get("redacted"):
                    tool_output = result["redacted"]
                    print_security("✎", YELLOW, "Passed tool.after", "(redacted)")
                else:
                    print_security("✓", GREEN, "Passed tool.after")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": tool_output,
                })

        # If there were tool calls, send results back to Claude and loop
        if tool_results:
            messages.append({"role": "assistant", "content": assistant_content})
            messages.append({"role": "user", "content": tool_results})
            continue

        # No more tool calls — done
        messages.append({"role": "assistant", "content": assistant_content})
        break


def main() -> None:
    global EVAL_URL

    parser = argparse.ArgumentParser(description="OpenClaw Security Platform — Chat Demo")
    parser.add_argument("--api-key", default=None, help="Anthropic API key (or set ANTHROPIC_API_KEY)")
    parser.add_argument("--eval-url", default=EVAL_URL, help="Evaluation server URL")
    args = parser.parse_args()

    EVAL_URL = args.eval_url

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(f"\n  {RED}No API key provided.{RESET}")
        print(f"  {DIM}Use --api-key or set ANTHROPIC_API_KEY{RESET}\n")
        sys.exit(1)

    # Health check against eval server
    try:
        health = httpx.get(f"{EVAL_URL}/health", timeout=3.0).json()
    except httpx.ConnectError:
        print(f"\n  {RED}Cannot connect to evaluation server at {EVAL_URL}{RESET}")
        print(f"  {DIM}Start the server first:  openclaw-security -c demo-chat-config.yaml{RESET}\n")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    messages: list[dict] = []

    print()
    print(f"  {BOLD}OpenClaw Security Platform — Chat Demo{RESET}")
    print(f"  {DIM}Agent: Claude (claude-sonnet-4-20250514) with tools: run_shell, read_file{RESET}")
    print(f"  {DIM}Security: {EVAL_URL} — {health['evaluators']} evaluators loaded{RESET}")
    print(f"  {DIM}Session: {SESSION_ID}{RESET}")
    print()
    print(f"  {DIM}Try messages with the words {RED}red{RESET}{DIM}, {YELLOW}yellow{RESET}{DIM}, or {GREEN}green{RESET}{DIM} to trigger blocks.{RESET}")
    print(f"  {DIM}Type 'quit' to exit.{RESET}")
    print()

    while True:
        try:
            message = input(f"  {CYAN}you ➤{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not message:
            continue
        if message.lower() in ("quit", "exit", "q"):
            break

        # --- Security: message.before ---
        result = evaluate("message.before", message_text=message)
        if result["blocked"]:
            print_block("message.before", result["reasons"])
            print()
            continue
        print_security("✓", GREEN, "Passed message.before")

        # Add to conversation and run the agent
        messages.append({"role": "user", "content": message})
        try:
            run_agent_loop(client, messages)
        except anthropic.APIError as e:
            print(f"\n  {RED}API error: {e}{RESET}")
        print()

    print(f"\n  {DIM}Session ended.{RESET}\n")


if __name__ == "__main__":
    main()
