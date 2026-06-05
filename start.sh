#!/usr/bin/env bash
# Start the BobaxDR server and local endpoint agent together.
# The API key is auto-read from .api_key after first server launch.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="$SCRIPT_DIR/.api_key"

# ── Start server ──────────────────────────────────────────────────────────────
echo "Starting BobaxDR server on :8000 …"
cd "$SCRIPT_DIR/server"
python3 main.py &
SERVER_PID=$!
cd "$SCRIPT_DIR"

# Wait for the key file to appear (generated on first launch)
echo -n "Waiting for API key"
for i in $(seq 1 30); do
  [ -f "$KEY_FILE" ] && break
  echo -n "."
  sleep 1
done
echo ""

if [ ! -f "$KEY_FILE" ]; then
  echo "ERROR: .api_key not generated after 30s — check server logs"
  kill $SERVER_PID 2>/dev/null
  exit 1
fi

export BOBAXDR_API_KEY="$(cat "$KEY_FILE")"
export BOBAXDR_SERVER="http://localhost:8000"

# ── Start local agent ─────────────────────────────────────────────────────────
echo "Starting local endpoint agent …"
cd "$SCRIPT_DIR/agent"
python3 agent.py &
AGENT_PID=$!
cd "$SCRIPT_DIR"

echo ""
echo "BobaxDR running."
echo "  Dashboard : http://localhost:8000"
echo "  Server PID: $SERVER_PID"
echo "  Agent PID : $AGENT_PID"
echo "  API key   : $BOBAXDR_API_KEY"
echo ""
echo "Press Ctrl+C to stop everything."

trap "kill $SERVER_PID $AGENT_PID 2>/dev/null; echo 'Stopped.'" EXIT INT TERM
wait $SERVER_PID
