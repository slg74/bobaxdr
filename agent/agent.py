#!/usr/bin/env python3
"""
BobaxDR Endpoint Agent
Cross-platform (macOS / Windows / Linux)

Usage:
  export BOBAXDR_SERVER=http://<server-ip>:8000
  export BOBAXDR_API_KEY=<key-from-server-startup>
  python3 agent.py
"""
import os
import sys
import time
import socket
import platform
import logging
import threading

import requests

sys.path.insert(0, os.path.dirname(__file__))
from process_monitor import get_processes
from network_monitor import get_connections

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
logger = logging.getLogger("bobaxdr-agent")

SERVER = os.environ.get("BOBAXDR_SERVER", "http://localhost:8000").rstrip("/")
API_KEY = os.environ.get("BOBAXDR_API_KEY", "")
PROC_SECS = int(os.environ.get("BOBAXDR_PROC_INTERVAL", "30"))
NET_SECS = int(os.environ.get("BOBAXDR_NET_INTERVAL", "10"))
HOSTNAME = socket.gethostname()
PLATFORM = platform.system().lower()

_session = requests.Session()
_session.headers["x-api-key"] = API_KEY
_session.headers["content-type"] = "application/json"


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def post(data: dict):
    try:
        r = _session.post(f"{SERVER}/api/events", json=data, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        logger.warning(f"Post failed: {e}")


def _base() -> dict:
    return {"hostname": HOSTNAME, "platform": PLATFORM, "ip_address": local_ip()}


def process_loop():
    # Warm up CPU percent counters (first call always returns 0)
    import psutil

    psutil.cpu_percent(interval=None)
    time.sleep(1)

    while True:
        try:
            procs = get_processes()
            post({**_base(), "type": "process_snapshot", "processes": procs})
            logger.debug(f"Reported {len(procs)} processes")
        except Exception as e:
            logger.error(f"Process loop: {e}")
        time.sleep(PROC_SECS)


def network_loop():
    while True:
        try:
            conns = get_connections()
            if conns:
                post({**_base(), "type": "network_connections", "connections": conns})
                logger.debug(f"Reported {len(conns)} connections")
        except Exception as e:
            logger.error(f"Network loop: {e}")
        time.sleep(NET_SECS)


def main():
    if not API_KEY:
        logger.error("BOBAXDR_API_KEY is not set.")
        logger.error("  export BOBAXDR_API_KEY=<key shown when server started>")
        sys.exit(1)

    logger.info(f"BobaxDR agent — {HOSTNAME} ({PLATFORM})")
    logger.info(f"Server: {SERVER}")
    logger.info(f"Intervals: processes every {PROC_SECS}s, network every {NET_SECS}s")

    threads = [
        threading.Thread(target=process_loop, name="proc", daemon=True),
        threading.Thread(target=network_loop, name="net", daemon=True),
    ]
    for t in threads:
        t.start()

    logger.info("Agent running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Agent stopped.")


if __name__ == "__main__":
    main()
