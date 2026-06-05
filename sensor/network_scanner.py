#!/usr/bin/env python3
"""
Network device scanner — discovers all devices on the local subnet via ARP.
Runs as part of the sensor, reports to BobaxDR server.

With sudo + scapy:  full ARP sweep (finds everything, including silent devices)
Without sudo:       parses arp -a + nmap ping sweep (finds recently active devices)
"""
import os
import re
import socket
import subprocess
import logging
import threading
import time

import requests

logger = logging.getLogger(__name__)

SCAN_INTERVAL = int(os.environ.get("BOBAXDR_SCAN_INTERVAL", "300"))  # 5 minutes


def _local_subnet() -> str:
    """Best-effort: derive /24 subnet from local IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan_with_scapy(subnet: str) -> list[dict]:
    """Full ARP sweep — needs root."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        return []

    devices = []
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                     timeout=3, verbose=False)
        for _, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc
            devices.append({"ip": ip, "mac": mac, "hostname": _hostname(ip)})
    except Exception as e:
        logger.warning(f"Scapy ARP sweep failed: {e}")
    return devices


def scan_with_nmap(subnet: str) -> list[dict]:
    """Ping sweep via nmap — no root needed."""
    devices = []
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", "-T4", subnet, "--open"],
            stderr=subprocess.DEVNULL, timeout=60,
        ).decode()
        # Parse nmap output for IPs and hostnames
        current = {}
        for line in out.splitlines():
            m = re.search(r"Nmap scan report for (.+?) \(?([\d.]+)\)?$", line)
            if m:
                host, ip = m.group(1).strip(), m.group(2)
                current = {"ip": ip, "mac": "", "hostname": host if host != ip else ""}
                devices.append(current)
            elif "MAC Address:" in line and current:
                mac_m = re.search(r"MAC Address: ([\w:]+)", line)
                if mac_m:
                    current["mac"] = mac_m.group(1).lower()
    except FileNotFoundError:
        logger.debug("nmap not found — falling back to arp -a")
    except subprocess.TimeoutExpired:
        logger.warning("nmap scan timed out")
    except Exception as e:
        logger.warning(f"nmap scan failed: {e}")
    return devices


def scan_arp_cache() -> list[dict]:
    """Parse arp -a — no root, no nmap needed. Shows recently seen devices only."""
    devices = []
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode()
        # Example: scottgs-MBP.lan (192.168.1.153) at a4:c3:f0:12:34:56 on en0
        # Or:      ? (192.168.1.1) at 00:11:22:aa:bb:cc [ether] on eth0
        for line in out.splitlines():
            m = re.search(r"\(?([\d.]+)\)?\s+at\s+([\w:]+)", line)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2).lower()
            if mac in ("ff:ff:ff:ff:ff:ff", "<incomplete>", "incomplete"):
                continue
            host_m = re.match(r"^(\S+)\s+\(", line)
            hostname = host_m.group(1) if host_m and host_m.group(1) != "?" else ""
            devices.append({"ip": ip, "mac": mac, "hostname": hostname})
    except Exception as e:
        logger.warning(f"arp -a failed: {e}")
    return devices


def run_scan(subnet: str) -> list[dict]:
    """Run all available scan methods and merge results by IP."""
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    merged: dict[str, dict] = {}

    def add(devices):
        for d in devices:
            ip = d.get("ip", "")
            if not ip:
                continue
            if ip not in merged:
                merged[ip] = d
            else:
                # Fill in missing fields from additional sources
                if not merged[ip].get("mac") and d.get("mac"):
                    merged[ip]["mac"] = d["mac"]
                if not merged[ip].get("hostname") and d.get("hostname"):
                    merged[ip]["hostname"] = d["hostname"]

    # Always start with ARP cache — most complete for currently active devices
    add(scan_arp_cache())

    # Supplement with nmap for devices not yet in cache
    add(scan_with_nmap(subnet))

    # Full ARP sweep if root
    if is_root:
        add(scan_with_scapy(subnet))

    devices = list(merged.values())
    logger.info(f"Network scan complete: {len(devices)} devices on {subnet}")
    return devices


def scanner_loop(server_url: str, api_key: str, hostname: str):
    subnet = _local_subnet()
    logger.info(f"Network scanner starting — subnet {subnet}, interval {SCAN_INTERVAL}s")

    session = requests.Session()
    session.headers["x-api-key"] = api_key

    while True:
        try:
            devices = run_scan(subnet)
            if devices:
                session.post(f"{server_url}/api/events", json={
                    "type": "network_scan",
                    "hostname": hostname,
                    "platform": "sensor",
                    "devices": devices,
                }, timeout=10)
        except Exception as e:
            logger.error(f"Scanner loop error: {e}")
        time.sleep(SCAN_INTERVAL)


def start(server_url: str, api_key: str, hostname: str):
    t = threading.Thread(
        target=scanner_loop,
        args=(server_url, api_key, hostname),
        daemon=True,
        name="net-scanner",
    )
    t.start()
    return t
