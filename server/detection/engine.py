import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List

from sqlalchemy.orm import Session

from models import Alert
from detection.threat_intel import ThreatIntel

logger = logging.getLogger(__name__)

# Processes that legitimately make many connections — suppress false positives
# Comparison is lowercased, so "Google" matches "google" etc.
BENIGN_PROCESSES = {
    "chrome", "firefox", "safari", "msedge", "opera", "brave", "arc",
    "slack", "zoom", "teams", "discord", "spotify", "steam",
    "dropbox", "onedrive", "icloud", "backblaze",
    "softwareupdate", "com.apple.trustd", "com.apple.security",
    "system", "svchost", "lsass", "services", "wininit",
    "node", "java", "python", "python3",
    # Google background processes (updater / Keystone, keepalive to GitHub etc.)
    "google", "googleupdate", "googlecrashhandler", "keystone",
    # Steam — high connection volume to CDN/matchmaking/presence servers; not a C2 vector
    "steam", "steam_osx", "steamwebhelper",
    # VS Code — helper processes beacon to Azure for telemetry/extension sync
    "code", "code helper", "code h",
    # Claude Code — persistent connection to Anthropic API while active
    "claude",
}


def _is_benign(proc: str) -> bool:
    """True if the process name matches a known-benign entry.
    Handles both exact matches and prefix matches for truncated lsof names."""
    p = proc.lower()
    if p in BENIGN_PROCESSES:
        return True
    return any(p.startswith(b) for b in BENIGN_PROCESSES)

SUSPICIOUS_PATHS = [
    "/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/",
    "/downloads/",
    "\\downloads\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
    "c:\\windows\\temp\\",
    "/library/caches/",
]

# Private IP prefixes
PRIVATE_PREFIXES = (
    "10.", "127.", "::1", "0.",
    "192.168.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)

DEDUP_WINDOW_MINUTES = 10


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


class DetectionEngine:
    def __init__(self, threat_intel: ThreatIntel):
        self.ti = threat_intel
        # beaconing: (hostname, dst_ip, proc) -> deque of datetimes
        self._beacon: Dict[tuple, deque] = defaultdict(lambda: deque(maxlen=50))

    # Called as a background task — creates its own DB session
    def run_detection(self, event_data: dict, endpoint_id: int):
        from database import SessionLocal
        db = SessionLocal()
        try:
            self.analyze(db, event_data, endpoint_id)
        except Exception:
            logger.exception("Detection engine error")
        finally:
            db.close()

    def analyze(self, db: Session, event_data: dict, endpoint_id: int):
        etype = event_data.get("type")
        hostname = event_data.get("hostname", "unknown")

        if etype == "process_snapshot":
            self._check_processes(db, event_data.get("processes", []), endpoint_id, hostname)
        elif etype == "network_connections":
            self._check_connections(db, event_data.get("connections", []), endpoint_id, hostname)
        elif etype == "dns_query":
            self._check_dns(db, event_data, endpoint_id, hostname)
        elif etype == "port_scan_detected":
            self._alert(db, endpoint_id, hostname, "PORT_SCAN_INBOUND", "high",
                        "Inbound port scan detected",
                        f"Port scan from {event_data.get('src_ip')} hit "
                        f"{len(event_data.get('ports_scanned', []))} ports",
                        event_data.get("src_ip", ""))

    def _check_processes(self, db, processes: List[dict], endpoint_id: int, hostname: str):
        for p in processes:
            name = p.get("name", "")
            exe = (p.get("exe") or "").lower()
            cpu = p.get("cpu_percent", 0) or 0

            if self.ti.is_miner_process(name):
                self._alert(db, endpoint_id, hostname, "CRYPTO_MINER", "critical",
                            f"Crypto miner process detected: {name}",
                            f"PID {p.get('pid')} matches known miner signature",
                            name)
                continue

            # Suspicious executable path
            if exe:
                for bad in SUSPICIOUS_PATHS:
                    if bad in exe:
                        self._alert(db, endpoint_id, hostname, "SUSPICIOUS_PROCESS_PATH", "high",
                                    "Process executing from suspicious path",
                                    f"'{name}' (PID {p.get('pid')}) running from: {p.get('exe')}",
                                    p.get("exe", ""))
                        break

            # High CPU + connection to mining port = heuristic miner
            if cpu > 85 and not _is_benign(name):
                for conn in p.get("connections", []):
                    if self.ti.is_mining_port(conn.get("rport", 0)):
                        self._alert(db, endpoint_id, hostname, "CRYPTO_MINER_HEURISTIC", "high",
                                    "Suspected crypto miner (high CPU + mining pool port)",
                                    f"'{name}' at {cpu:.0f}% CPU connected to port {conn.get('rport')}",
                                    name)
                        break

    def _check_connections(self, db, connections: List[dict], endpoint_id: int, hostname: str):
        now = datetime.utcnow()
        proc_dst: Dict[str, set] = defaultdict(set)

        for c in connections:
            dst_ip = c.get("raddr", "")
            dst_port = c.get("rport", 0)
            proc = c.get("process", "unknown")

            if not dst_ip or _is_private(dst_ip):
                continue

            # Known-bad IP
            if self.ti.is_malicious_ip(dst_ip):
                self._alert(db, endpoint_id, hostname, "MALICIOUS_IP_CONNECTION", "critical",
                            "Connection to known malicious C2 IP",
                            f"'{proc}' connected to threat-intel flagged IP {dst_ip}:{dst_port}",
                            dst_ip)

            # Beaconing + scan detection — skip known-benign processes
            if not _is_benign(proc):
                key = (hostname, dst_ip, proc)
                self._beacon[key].append(now)
                self._check_beaconing(db, endpoint_id, hostname, key, dst_ip, proc)
                proc_dst[proc].add((dst_ip, dst_port))

        # Outbound port scan heuristic: one process hitting many unique targets fast
        for proc, targets in proc_dst.items():
            if len(targets) > 20:
                self._alert(db, endpoint_id, hostname, "PORT_SCAN_OUTBOUND", "medium",
                            "Outbound port scanning behavior detected",
                            f"'{proc}' made {len(targets)} unique external connections in one interval",
                            proc)

    def _check_beaconing(self, db, endpoint_id, hostname, key, dst_ip, proc):
        ts = list(self._beacon[key])
        if len(ts) < 8:
            return

        intervals = [
            (ts[i] - ts[i - 1]).total_seconds()
            for i in range(1, len(ts))
            if 1 < (ts[i] - ts[i - 1]).total_seconds() < 3600
        ]
        if len(intervals) < 6:
            return

        avg = sum(intervals) / len(intervals)
        if avg < 1:
            return
        std = (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5
        cv = std / avg

        # Very regular interval (CV < 15%) between 5s and 5min → beaconing
        if cv < 0.15 and 5 <= avg <= 300:
            self._alert(db, endpoint_id, hostname, "C2_BEACONING", "high",
                        "C2 beaconing pattern detected",
                        f"'{proc}' connecting to {dst_ip} every ~{avg:.0f}s (regularity CV={cv:.2f})",
                        dst_ip)
            self._beacon[key].clear()

    def _check_dns(self, db, event_data: dict, endpoint_id: int, hostname: str):
        domain = (event_data.get("domain") or "").lower().rstrip(".")
        dst_ip = event_data.get("dst_ip", "")
        dst_port = event_data.get("dst_port", 53)

        if not domain:
            return

        if self.ti.is_malicious_domain(domain):
            self._alert(db, endpoint_id, hostname, "MALICIOUS_DOMAIN_DNS", "high",
                        "DNS query for known malicious domain",
                        f"Device queried threat-intel flagged domain: {domain}",
                        domain)

        # DNS tunneling — query on non-standard port, external destination only
        # (ephemeral ports on private IPs are normal DNS response routing)
        if dst_port not in (53, 853, 5353) and dst_ip and not _is_private(dst_ip):
            self._alert(db, endpoint_id, hostname, "DNS_TUNNELING", "medium",
                        "DNS over non-standard port (possible tunneling)",
                        f"DNS query to {dst_ip}:{dst_port} — standard is 53/853",
                        f"{dst_ip}:{dst_port}")

        # Query routed to unknown external DNS server
        if dst_ip and not _is_private(dst_ip) and not self.ti.is_trusted_dns(dst_ip):
            self._alert(db, endpoint_id, hostname, "SUSPICIOUS_DNS_SERVER", "medium",
                        "DNS query to unrecognized external server",
                        f"DNS request for '{domain}' sent to {dst_ip} (not Spectrum or common public DNS)",
                        dst_ip)

    def _alert(self, db: Session, endpoint_id: int, hostname: str,
               rule: str, severity: str, title: str, description: str, indicator: str):
        window = datetime.utcnow() - timedelta(minutes=DEDUP_WINDOW_MINUTES)
        exists = db.query(Alert).filter(
            Alert.endpoint_id == endpoint_id,
            Alert.rule_name == rule,
            Alert.indicator == indicator,
            Alert.timestamp > window,
            Alert.acknowledged == False,
        ).first()
        if exists:
            return

        a = Alert(
            endpoint_id=endpoint_id,
            endpoint_hostname=hostname,
            rule_name=rule,
            severity=severity,
            title=title,
            description=description,
            indicator=indicator,
            timestamp=datetime.utcnow(),
        )
        db.add(a)
        db.commit()
        logger.warning(f"[ALERT:{severity.upper()}] {title} | host={hostname} | {indicator}")
