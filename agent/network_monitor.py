import logging
import psutil

logger = logging.getLogger(__name__)


def _proc_name(pid: int | None) -> str:
    if not pid:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def get_connections() -> list[dict]:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            ip = c.raddr.ip
            if not ip or ip in ("0.0.0.0", "::", ""):
                continue
            conns.append({
                "raddr": ip,
                "rport": c.raddr.port,
                "lport": c.laddr.port if c.laddr else None,
                "status": c.status,
                "pid": c.pid,
                "process": _proc_name(c.pid),
            })
    except (psutil.AccessDenied, PermissionError):
        logger.debug("Limited access to connection list — try running as administrator/root for full visibility")

    return conns
