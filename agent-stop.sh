#!/usr/bin/env bash
PID_FILE="/tmp/bobaxdr-agent.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "No PID file found — agent may not be running"
  exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "Agent stopped (PID $PID)"
else
  echo "Agent was not running (stale PID $PID)"
fi

rm -f "$PID_FILE"
