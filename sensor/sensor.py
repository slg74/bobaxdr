#!/usr/bin/env python3
"""
BobaxDR Network Sensor
Monitors raw network traffic — DNS queries, port scans, C2 connections.

Full mode (recommended):  sudo python3 sensor/sensor.py
Fallback mode (no root):  python3 sensor/sensor.py

Requires: pip install scapy psutil requests
"""
import os
import sys
import time
import socket
import logging
import ipaddress
import threading
from collections import defaultdict
from datetime import datetime

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("bobaxdr-sensor")

SERVER = os.environ.get("BOBAXDR_SERVER", "http://localhost:8000").rstrip("/")
API_KEY = os.environ.get("BOBAXDR_API_KEY", "")
HOSTNAME = socket.gethostname()

_session = requests.Session()
_session.headers["x-api-key"] = API_KEY

PRIVATE_PREFIXES = (
    "10.",
    "127.",
    "::1",
    "169.254.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
)

# Well-known domains and their IP cache for hijack detection
_dns_baseline: dict[str, str] = {}
_dns_baseline_lock = threading.Lock()

PROBE_DOMAINS = [
    "google.com",
    "cloudflare.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "github.com",
]


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def post(data: dict):
    try:
        r = _session.post(f"{SERVER}/api/events", json=data, timeout=10)
        r.raise_for_status()
    except requests.RequestException as e:
        logger.warning(f"Post failed: {e}")


# ── DNS hijack monitor (no root required) ────────────────────────────────────
def _resolve(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def build_dns_baseline():
    logger.info("Building DNS baseline (resolving probe domains)…")
    with _dns_baseline_lock:
        for d in PROBE_DOMAINS:
            ip = _resolve(d)
            if ip:
                _dns_baseline[d] = ip
                logger.info(f"  {d} → {ip}")
    logger.info("DNS baseline ready.")


def dns_hijack_monitor():
    build_dns_baseline()
    while True:
        time.sleep(300)
        with _dns_baseline_lock:
            for domain, expected in list(_dns_baseline.items()):
                current = _resolve(domain)
                if not current:
                    continue
                exp_oct = expected.split(".")[:2]
                cur_oct = current.split(".")[:2]
                if exp_oct != cur_oct:
                    logger.warning(f"DNS anomaly: {domain} → {current} (baseline: {expected})")
                    post(
                        {
                            "type": "dns_query",
                            "hostname": HOSTNAME,
                            "domain": domain,
                            "src_ip": "",
                            "dst_ip": current,
                            "dst_port": 53,
                            "note": f"resolved to {current}, baseline was {expected}",
                        }
                    )
                    _dns_baseline[domain] = current


# ── Scapy packet-capture mode (requires root) ────────────────────────────────
def run_scapy():
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
    except ImportError:
        logger.warning("scapy not installed — run: pip3 install scapy")
        return False

    logger.info("Packet capture active (scapy). Monitoring DNS + TCP SYN scans.")

    # Track inbound SYN packets per source IP: src_ip → [(ts, dst_port)]
    syn_state: dict[str, list] = defaultdict(list)

    def handle(pkt):
        try:
            if not pkt.haslayer(IP):
                return
            src = pkt[IP].src
            dst = pkt[IP].dst

            # ── DNS queries ──────────────────────────────────────────────────
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                domain = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                dst_port = pkt[UDP].dport if pkt.haslayer(UDP) else 53
                post(
                    {
                        "type": "dns_query",
                        "hostname": HOSTNAME,
                        "domain": domain,
                        "src_ip": src,
                        "dst_ip": dst,
                        "dst_port": dst_port,
                    }
                )

            # ── Inbound TCP SYN scan detection ───────────────────────────────
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                # SYN-only (not SYN-ACK)
                if tcp.flags == 0x002 and not _is_private(src):
                    now = time.time()
                    syn_state[src].append((now, tcp.dport))
                    # Evict entries older than 60s
                    syn_state[src] = [(t, p) for t, p in syn_state[src] if now - t < 60]
                    unique_ports = {p for _, p in syn_state[src]}
                    if len(unique_ports) >= 10:
                        logger.warning(f"Port scan detected from {src} ({len(unique_ports)} ports)")
                        post(
                            {
                                "type": "port_scan_detected",
                                "hostname": HOSTNAME,
                                "src_ip": src,
                                "ports_scanned": list(unique_ports),
                            }
                        )
                        syn_state[src].clear()
        except Exception:
            pass

    sniff(prn=handle, store=False, filter="tcp or udp port 53")
    return True


# ── psutil fallback mode (no root) ────────────────────────────────────────────
def run_psutil_fallback():
    try:
        import psutil
    except ImportError:
        logger.error("psutil not installed — run: pip3 install psutil")
        return

    logger.info("Connection monitoring active (psutil, no packet capture).")
    logger.info("For full DNS + port scan detection, run: sudo python3 sensor/sensor.py")

    prev: set[tuple] = set()
    while True:
        try:
            cur: set[tuple] = set()
            for c in psutil.net_connections(kind="inet"):
                if c.raddr and c.status == "ESTABLISHED":
                    cur.add((c.raddr.ip, c.raddr.port))
            new = cur - prev
            for ip, port in new:
                if not _is_private(ip):
                    logger.debug(f"New external conn: {ip}:{port}")
            prev = cur
        except Exception as e:
            logger.error(f"psutil fallback: {e}")
        time.sleep(5)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    if not API_KEY:
        logger.error("BOBAXDR_API_KEY is not set.")
        sys.exit(1)

    logger.info(f"BobaxDR sensor — {HOSTNAME}")
    logger.info(f"Reporting to {SERVER}")

    # DNS hijack monitor + network device scanner run regardless of privilege level
    threading.Thread(target=dns_hijack_monitor, daemon=True, name="dns-hijack").start()

    sys.path.insert(0, os.path.dirname(__file__))
    import network_scanner

    network_scanner.start(SERVER, API_KEY, HOSTNAME)

    # Use packet capture if root, otherwise fall back to connection monitoring
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        # Windows
        import ctypes

        is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if is_root:
        run_scapy()
    else:
        logger.warning("Not running as root — packet capture unavailable.")
        logger.warning("Upgrade: sudo BOBAXDR_API_KEY=$BOBAXDR_API_KEY python3 sensor/sensor.py")
        run_psutil_fallback()


if __name__ == "__main__":
    main()
