#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="/tmp/bobaxdr-agent.pid"
LOG_FILE="/tmp/bobaxdr-agent.log"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Agent already running (PID $(cat "$PID_FILE"))"
  exit 0
fi

# Resolve agent directory — support both repo layout (agent/) and standalone copy
if [ -f "$SCRIPT_DIR/agent/agent.py" ]; then
  AGENT_DIR="$SCRIPT_DIR/agent"
elif [ -f "$SCRIPT_DIR/agent.py" ]; then
  AGENT_DIR="$SCRIPT_DIR"
else
  echo "ERROR: cannot find agent.py under $SCRIPT_DIR"
  exit 1
fi

# Prefer venv if present, then system python3
if [ -x "$AGENT_DIR/venv/bin/python" ]; then
  PYTHON="$AGENT_DIR/venv/bin/python"
elif [ -x "$SCRIPT_DIR/venv/bin/python" ]; then
  PYTHON="$SCRIPT_DIR/venv/bin/python"
else
  PYTHON=python3
fi

# API key: env var takes precedence, then read from local key file (co-located server)
if [ -z "${BOBAXDR_API_KEY:-}" ]; then
  KEY_FILE="$SCRIPT_DIR/.api_key"
  if [ ! -f "$KEY_FILE" ]; then
    echo "ERROR: BOBAXDR_API_KEY not set and no .api_key file found"
    echo "  Set it with: export BOBAXDR_API_KEY=<key>"
    exit 1
  fi
  export BOBAXDR_API_KEY="$(cat "$KEY_FILE")"
fi

# Server address: env var or default to localhost
export BOBAXDR_SERVER="${BOBAXDR_SERVER:-http://localhost:8000}"

echo "Starting BobaxDR agent…"
echo "  Python  : $PYTHON"
echo "  Server  : $BOBAXDR_SERVER"
echo "  Log     : $LOG_FILE"

cd "$AGENT_DIR"
"$PYTHON" agent.py >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

echo "Agent running (PID $(cat "$PID_FILE"))"
