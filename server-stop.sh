#!/usr/bin/env bash
PID_FILE="/tmp/bobaxdr-server.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "No PID file found — server may not be running"
  exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo "Server stopped (PID $PID)"
else
  echo "Server was not running (stale PID $PID)"
fi

rm -f "$PID_FILE"
