#!/usr/bin/env bash

stop_pid() {
  local name="$1" pid_file="$2"
  if [ ! -f "$pid_file" ]; then
    return
  fi
  local pid
  pid=$(cat "$pid_file")
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    echo "$name stopped (PID $pid)"
  else
    echo "$name was not running (stale PID $pid)"
  fi
  rm -f "$pid_file"
}

stop_pid "k8s poller"    /tmp/bobaxdr-k8s.pid
stop_pid "Docker poller" /tmp/bobaxdr-docker.pid
stop_pid "AWS poller"    /tmp/bobaxdr-aws.pid
stop_pid "Server"        /tmp/bobaxdr-server.pid

# Kill any orphaned poller/server processes not captured by PID files
pkill -f "k8s_poller.py"    2>/dev/null
pkill -f "docker_poller.py" 2>/dev/null
pkill -f "aws_poller.py"    2>/dev/null
