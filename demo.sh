#!/usr/bin/env bash
#
# OpenClaw Security Platform — Demo Script
#
# Usage:
#   Terminal 1:  python3 -m uvicorn openclaw_security.server:app --host 127.0.0.1 --port 9920 --log-level debug
#   Terminal 2:  bash demo.sh
#
# The server must be running with demo-config.yaml:
#   OPENCLAW_SECURITY_CONFIG=demo-config.yaml python3 -m uvicorn openclaw_security.server:app --host 127.0.0.1 --port 9920 --log-level debug

set -e
URL="http://127.0.0.1:9920"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

divider() {
  echo ""
  echo -e "${DIM}────────────────────────────────────────────────────────────${RESET}"
  echo ""
}

banner() {
  echo -e "${CYAN}${BOLD}$1${RESET}"
}

pause() {
  echo ""
  echo -e "${DIM}  Press Enter to continue...${RESET}"
  read -r
}

echo ""
echo -e "${BOLD}  ╔═══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}  ║   OpenClaw Security Platform — Live Demo      ║${RESET}"
echo -e "${BOLD}  ║   Bring-Your-Own-Security for AI Agents       ║${RESET}"
echo -e "${BOLD}  ╚═══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Health check ──────────────────────────────────────────
banner "▸ Health Check"
echo -e "  ${DIM}GET /health${RESET}"
echo ""
curl -s "$URL/health" | python3 -m json.tool
pause

# ═══════════════════════════════════════════════════════════
# BLOCKED REQUESTS
# ═══════════════════════════════════════════════════════════

divider
banner "▸ BLOCK: Dangerous command — rm -rf /"
echo -e "  ${DIM}An agent tries to execute a recursive delete${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.before",
    "session_id": "demo-sess-001",
    "tool_name": "exec",
    "tool_args": {"command": "rm -rf / --no-preserve-root"}
  }' | python3 -m json.tool
pause

divider
banner "▸ BLOCK: SQL injection — DROP TABLE"
echo -e "  ${DIM}A prompt-injected query tries to drop a table${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.before",
    "session_id": "demo-sess-002",
    "tool_name": "exec",
    "tool_args": {"command": "psql -c \"DROP TABLE users CASCADE;\""}
  }' | python3 -m json.tool
pause

divider
banner "▸ BLOCK: Private key in tool output"
echo -e "  ${DIM}A tool accidentally reads a private key file${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.after",
    "session_id": "demo-sess-003",
    "tool_name": "read_file",
    "tool_result": "File contents:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF...\n-----END RSA PRIVATE KEY-----"
  }' | python3 -m json.tool
pause

divider
banner "▸ BLOCK: Disk format command"
echo -e "  ${DIM}Agent tries to format a disk${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.before",
    "session_id": "demo-sess-004",
    "tool_name": "exec",
    "tool_args": {"command": "dd if=/dev/zero of=/dev/sda bs=1M"}
  }' | python3 -m json.tool
pause

# ═══════════════════════════════════════════════════════════
# REDACTED REQUESTS
# ═══════════════════════════════════════════════════════════

divider
banner "▸ REDACT: AWS Access Key in tool output"
echo -e "  ${DIM}Tool output contains an AWS key — redacted before reaching the model${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.after",
    "session_id": "demo-sess-005",
    "tool_name": "exec",
    "tool_result": "Config loaded successfully.\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1"
  }' | python3 -m json.tool
pause

divider
banner "▸ REDACT: GitHub token leaked in logs"
echo -e "  ${DIM}A GitHub PAT appears in command output${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.after",
    "session_id": "demo-sess-006",
    "tool_name": "exec",
    "tool_result": "remote: Invalid username or password.\nfatal: Authentication failed for https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij@github.com/org/repo.git"
  }' | python3 -m json.tool
pause

# ═══════════════════════════════════════════════════════════
# ALLOWED REQUESTS
# ═══════════════════════════════════════════════════════════

divider
banner "▸ ALLOW: Safe command — list files"
echo -e "  ${DIM}A normal ls command passes all evaluators${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.before",
    "session_id": "demo-sess-007",
    "tool_name": "exec",
    "tool_args": {"command": "ls -la /home/user/project/"}
  }' | python3 -m json.tool
pause

divider
banner "▸ ALLOW: Clean tool output"
echo -e "  ${DIM}Build output with no secrets — passes through${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.after",
    "session_id": "demo-sess-008",
    "tool_name": "exec",
    "tool_result": "Build succeeded.\n✓ 247 tests passed\n✓ 0 failures\n✓ Coverage: 94.2%\nArtifact: dist/app-v2.1.0.tar.gz (12.4 MB)"
  }' | python3 -m json.tool
pause

divider
banner "▸ ALLOW: Safe file read"
echo -e "  ${DIM}Reading a normal config file — no secrets detected${RESET}"
echo ""
curl -s -X POST "$URL/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "stage": "tool.after",
    "session_id": "demo-sess-009",
    "tool_name": "read_file",
    "tool_result": "# Application Config\napp_name: my-service\nport: 8080\nlog_level: info\nmax_connections: 100"
  }' | python3 -m json.tool
pause

# ═══════════════════════════════════════════════════════════

divider
echo -e "${GREEN}${BOLD}  ✓ Demo complete${RESET}"
echo ""
echo -e "  ${DIM}Blocked: 4  |  Redacted: 2  |  Allowed: 3${RESET}"
echo -e "  ${DIM}All decisions made in < 5ms with zero API calls${RESET}"
echo ""
