import logging
import psutil

logger = logging.getLogger(__name__)


def get_processes() -> list[dict]:
    procs = []
    for p in psutil.process_iter(
        ["pid", "name", "exe", "cpu_percent", "memory_percent", "status", "cmdline"]
    ):
        try:
            info = p.info
            if info.get("status") == psutil.STATUS_ZOMBIE:
                continue

            conns = []
            try:
                for c in p.net_connections():
                    if c.raddr:
                        conns.append(
                            {
                                "raddr": c.raddr.ip,
                                "rport": c.raddr.port,
                                "lport": c.laddr.port if c.laddr else None,
                            }
                        )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            procs.append(
                {
                    "pid": info["pid"],
                    "name": info.get("name") or "",
                    "exe": info.get("exe") or "",
                    "cpu_percent": round(info.get("cpu_percent") or 0, 1),
                    "memory_percent": round(info.get("memory_percent") or 0, 1),
                    "cmdline": " ".join(info.get("cmdline") or [])[:400],
                    "connections": conns,
                }
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

    return procs
