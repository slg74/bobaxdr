import os
import sys
import logging
import subprocess
import re

import psutil

logger = logging.getLogger(__name__)


def _proc_name(pid: int | None) -> str:
    if not pid:
        return "unknown"
    try:
        p = psutil.Process(pid)
        # On Linux, name() is capped at 15 chars by the kernel; use exe() for the full name
        if sys.platform != "darwin":
            try:
                exe = p.exe()
                if exe:
                    return os.path.basename(exe)
            except (psutil.AccessDenied, OSError):
                pass
        return p.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def _get_connections_lsof() -> list[dict]:
    """macOS: use lsof -i which works without root."""
    try:
        out = subprocess.check_output(
            ["lsof", "-i", "-n", "-P", "-sTCP:ESTABLISHED"],
            stderr=subprocess.DEVNULL,
            timeout=10,
        ).decode("utf-8", errors="ignore")
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    conns = []
    # Example line:
    # chrome  1234 user  45u  IPv4 0x1  0t0  TCP 10.0.0.5:52341->142.250.80.46:443 (ESTABLISHED)
    pattern = re.compile(
        r"(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+TCP\s+([\d.]+):(\d+)->([\d.]+):(\d+)"
    )
    for line in out.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        proc, pid, laddr, lport, raddr, rport = m.groups()
        conns.append(
            {
                "raddr": raddr,
                "rport": int(rport),
                "lport": int(lport),
                "status": "ESTABLISHED",
                "pid": int(pid),
                "process": proc,
            }
        )
    return conns


def _get_connections_psutil() -> list[dict]:
    """Linux / Windows: psutil works fine without root."""
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            ip = c.raddr.ip
            if not ip or ip in ("0.0.0.0", "::"):
                continue
            conns.append(
                {
                    "raddr": ip,
                    "rport": c.raddr.port,
                    "lport": c.laddr.port if c.laddr else None,
                    "status": c.status,
                    "pid": c.pid,
                    "process": _proc_name(c.pid),
                }
            )
    except (psutil.AccessDenied, PermissionError) as e:
        logger.debug(f"psutil net_connections: {e}")
    return conns


def get_connections() -> list[dict]:
    if sys.platform == "darwin":
        return _get_connections_lsof()
    return _get_connections_psutil()
