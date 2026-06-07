#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="/tmp/bobaxdr-server.pid"
LOG_FILE="/tmp/bobaxdr-server.log"
KEY_FILE="$SCRIPT_DIR/.api_key"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Server already running (PID $(cat "$PID_FILE"))"
  exit 0
fi

# Prefer Python 3.12, fall back to system python3
PYTHON=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3
[ -x "$PYTHON" ] || PYTHON=python3

echo "Starting BobaxDR server…"
cd "$SCRIPT_DIR/server"
"$PYTHON" main.py >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
cd "$SCRIPT_DIR"

# Wait for key file (generated on first run)
echo -n "Waiting for API key"
for i in $(seq 1 30); do
  [ -f "$KEY_FILE" ] && break
  echo -n "."
  sleep 1
done
echo ""

if [ ! -f "$KEY_FILE" ]; then
  echo "ERROR: key not generated — check $LOG_FILE"
  kill "$(cat "$PID_FILE")" 2>/dev/null
  rm -f "$PID_FILE"
  exit 1
fi

chmod 600 "$KEY_FILE"

echo "Server running (PID $(cat "$PID_FILE"))"
echo "  Dashboard : http://localhost:8000"
echo "  API key   : $(cat "$KEY_FILE")"
echo "  Log       : $LOG_FILE"
