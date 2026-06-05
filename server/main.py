import os
import sys
import secrets
import logging
import threading
import asyncio
import socket as _socket
import re as _re
from collections import defaultdict
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Header, BackgroundTasks, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

sys.path.insert(0, os.path.dirname(__file__))

from database import get_db, engine, Base
from models import Endpoint, Event, Alert, NetworkDevice
from detection.engine import DetectionEngine
from detection.threat_intel import ThreatIntel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("bobaxdr")

# ── API key ──────────────────────────────────────────────────────────────────
_key_file = os.path.join(os.path.dirname(__file__), "..", ".api_key")
if os.path.exists(_key_file):
    with open(_key_file) as f:
        API_KEY = f.read().strip()
else:
    API_KEY = secrets.token_hex(32)
    with open(_key_file, "w") as f:
        f.write(API_KEY)
    print("\n" + "=" * 60)
    print("BobaxDR — first run, API key generated")
    print(f"  API_KEY={API_KEY}")
    print("Copy this key into your agent and sensor configs.")
    print("=" * 60 + "\n")

# ── Core components ──────────────────────────────────────────────────────────
threat_intel = ThreatIntel()
engine_ = DetectionEngine(threat_intel)

_PRIVATE = ("10.", "127.", "::1", "169.254.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
            "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


class TopTalkersTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}

    def record(self, connections: list, hostname: str):
        now = datetime.utcnow()
        with self._lock:
            for c in connections:
                ip = c.get("raddr", "")
                if not ip or any(ip.startswith(p) for p in _PRIVATE):
                    continue
                if ip not in self._data:
                    self._data[ip] = {
                        "ip": ip,
                        "count": 0,
                        "endpoints": set(),
                        "processes": set(),
                        "ports": set(),
                        "first_seen": now,
                        "last_seen": now,
                    }
                d = self._data[ip]
                d["count"] += 1
                d["endpoints"].add(hostname)
                d["last_seen"] = now
                if c.get("process"):
                    d["processes"].add(c["process"])
                if c.get("rport"):
                    d["ports"].add(int(c["rport"]))

    def top(self, n: int = 30) -> list:
        with self._lock:
            items = sorted(self._data.values(), key=lambda x: x["count"], reverse=True)[:n]
            return [
                {
                    "ip": d["ip"],
                    "count": d["count"],
                    "endpoints": sorted(d["endpoints"]),
                    "processes": sorted(d["processes"])[:5],
                    "ports": sorted(d["ports"])[:8],
                    "first_seen": d["first_seen"].isoformat(),
                    "last_seen": d["last_seen"].isoformat(),
                    "is_malicious": threat_intel.is_malicious_ip(d["ip"]),
                }
                for d in items
            ]


talkers = TopTalkersTracker()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    try:
        await threat_intel.refresh()
    except Exception as e:
        logger.warning(f"Threat intel unavailable on startup: {e}")
    yield


app = FastAPI(title="BobaxDR", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ── Auth ─────────────────────────────────────────────────────────────────────
def auth(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ── Dashboard (no auth — served on local network only) ───────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    path = os.path.join(STATIC_DIR, "index.html")
    with open(path) as f:
        html = f.read()
    return HTMLResponse(html.replace("__API_KEY__", API_KEY))


# ── Event ingestion ───────────────────────────────────────────────────────────
@app.post("/api/events")
async def ingest_event(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _=Depends(auth),
):
    data = await request.json()
    hostname = data.get("hostname", "unknown")

    ep = db.query(Endpoint).filter(Endpoint.hostname == hostname).first()
    if not ep:
        ep = Endpoint(
            hostname=hostname,
            platform=data.get("platform", "unknown"),
            ip_address=data.get("ip_address", ""),
            first_seen=datetime.utcnow(),
        )
        db.add(ep)
        db.flush()

    ep.last_seen = datetime.utcnow()
    if data.get("ip_address"):
        ep.ip_address = data["ip_address"]

    ev = Event(
        endpoint_id=ep.id,
        event_type=data.get("type", "unknown"),
        data=str(data)[:4000],
        timestamp=datetime.utcnow(),
    )
    db.add(ev)
    db.commit()

    if data.get("type") == "network_connections":
        talkers.record(data.get("connections", []), hostname)

    if data.get("type") == "network_scan":
        background_tasks.add_task(_process_network_scan, data.get("devices", []))

    background_tasks.add_task(engine_.run_detection, data, ep.id)
    return {"status": "ok", "event_id": ev.id}


# ── Alerts ────────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
async def list_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    acknowledged: bool = False,
    db: Session = Depends(get_db),
    _=Depends(auth),
):
    q = db.query(Alert).filter(Alert.acknowledged == acknowledged)
    if severity:
        q = q.filter(Alert.severity == severity)
    return [a.to_dict() for a in q.order_by(Alert.timestamp.desc()).limit(limit)]


@app.put("/api/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: int, db: Session = Depends(get_db), _=Depends(auth)):
    a = db.query(Alert).filter(Alert.id == alert_id).first()
    if not a:
        raise HTTPException(status_code=404)
    a.acknowledged = True
    db.commit()
    return {"status": "ok"}


@app.post("/api/alerts/acknowledge-all")
async def ack_all_alerts(
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    _=Depends(auth),
):
    q = db.query(Alert).filter(Alert.acknowledged == False)
    if severity:
        q = q.filter(Alert.severity == severity)
    n = q.update({"acknowledged": True})
    db.commit()
    return {"acknowledged": n}


@app.delete("/api/alerts/acknowledged")
async def clear_acknowledged(db: Session = Depends(get_db), _=Depends(auth)):
    n = db.query(Alert).filter(Alert.acknowledged == True).delete()
    db.commit()
    return {"deleted": n}


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/api/endpoints")
async def list_endpoints(db: Session = Depends(get_db), _=Depends(auth)):
    return [e.to_dict() for e in db.query(Endpoint).all()]


# ── Latest snapshots (for the Events card modal) ──────────────────────────────
@app.get("/api/events/latest")
async def latest_snapshots(db: Session = Depends(get_db), _=Depends(auth)):
    import ast

    def parse(ev):
        try:
            return ast.literal_eval(ev.data)
        except Exception:
            return {}

    result = []
    # One latest snapshot of each type per endpoint
    endpoints = db.query(Endpoint).all()
    for ep in endpoints:
        for etype in ("process_snapshot", "network_connections"):
            ev = (
                db.query(Event)
                .filter(Event.endpoint_id == ep.id, Event.event_type == etype)
                .order_by(Event.timestamp.desc())
                .first()
            )
            if not ev:
                continue
            data = parse(ev)
            if etype == "process_snapshot":
                procs = data.get("processes", [])
                # Top 25 by CPU, filter out zero-everything idle entries
                top = sorted(procs, key=lambda p: p.get("cpu_percent", 0), reverse=True)[:25]
                result.append({
                    "type": "process_snapshot",
                    "hostname": ep.hostname,
                    "timestamp": ev.timestamp.isoformat(),
                    "processes": [
                        {
                            "name": p.get("name", ""),
                            "pid": p.get("pid"),
                            "cpu": p.get("cpu_percent", 0),
                            "mem": p.get("memory_percent", 0),
                            "exe": p.get("exe", ""),
                            "connections": len(p.get("connections", [])),
                        }
                        for p in top
                    ],
                })
            else:
                conns = data.get("connections", [])
                external = [
                    c for c in conns
                    if c.get("raddr") and not any(
                        c["raddr"].startswith(p)
                        for p in ("127.", "192.168.", "10.", "::1", "169.")
                    )
                ]
                result.append({
                    "type": "network_connections",
                    "hostname": ep.hostname,
                    "timestamp": ev.timestamp.isoformat(),
                    "connections": external,
                    "total": len(conns),
                })

    return result


# ── Dashboard stats ───────────────────────────────────────────────────────────
@app.get("/api/dashboard")
async def dashboard_stats(db: Session = Depends(get_db), _=Depends(auth)):
    since_24h = datetime.utcnow() - timedelta(hours=24)
    since_5m = datetime.utcnow() - timedelta(minutes=5)

    alerts_24h = db.query(Alert).filter(
        Alert.timestamp > since_24h, Alert.acknowledged == False
    ).count()
    critical_24h = db.query(Alert).filter(
        Alert.timestamp > since_24h,
        Alert.severity == "critical",
        Alert.acknowledged == False,
    ).count()
    active_ep = db.query(Endpoint).filter(Endpoint.last_seen > since_5m).count()
    total_ep = db.query(Endpoint).count()
    events_24h = db.query(Event).filter(Event.timestamp > since_24h).count()

    recent = db.query(Alert).order_by(Alert.timestamp.desc()).limit(20).all()

    return {
        "alerts_24h": alerts_24h,
        "critical_24h": critical_24h,
        "active_endpoints": active_ep,
        "total_endpoints": total_ep,
        "events_24h": events_24h,
        "recent_alerts": [a.to_dict() for a in recent],
        "threat_intel": threat_intel.status(),
    }


# ── Network scan processor ────────────────────────────────────────────────────
def _process_network_scan(devices: list):
    from database import SessionLocal
    db = SessionLocal()
    try:
        for d in devices:
            ip = d.get("ip", "")
            if not ip:
                continue
            existing = db.query(NetworkDevice).filter(NetworkDevice.ip == ip).first()
            if not existing:
                new_dev = NetworkDevice(
                    ip=ip,
                    mac=d.get("mac", ""),
                    hostname=d.get("hostname", ""),
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
                db.add(new_dev)
                db.flush()
                # Alert on new unknown device
                alert = Alert(
                    endpoint_hostname="network",
                    rule_name="NEW_NETWORK_DEVICE",
                    severity="medium",
                    title=f"New device joined the network",
                    description=f"Unknown device appeared at {ip} "
                                f"(MAC: {d.get('mac', 'unknown')}, "
                                f"hostname: {d.get('hostname', 'unknown')})",
                    indicator=ip,
                    timestamp=datetime.utcnow(),
                )
                db.add(alert)
                logger.warning(f"[NEW DEVICE] {ip}  mac={d.get('mac')}  host={d.get('hostname')}")
            else:
                # Detect MAC change — possible ARP spoofing
                old_mac = existing.mac
                new_mac = d.get("mac", "")
                if old_mac and new_mac and old_mac != new_mac:
                    alert = Alert(
                        endpoint_hostname="network",
                        rule_name="ARP_SPOOF_SUSPECTED",
                        severity="high",
                        title=f"ARP spoofing suspected — MAC changed for {ip}",
                        description=f"{ip} was {old_mac}, now answering as {new_mac}",
                        indicator=ip,
                        timestamp=datetime.utcnow(),
                    )
                    db.add(alert)
                    logger.warning(f"[ARP SPOOF] {ip} mac changed {old_mac} → {new_mac}")
                existing.last_seen = datetime.utcnow()
                if d.get("mac"):
                    existing.mac = d["mac"]
                if d.get("hostname"):
                    existing.hostname = d["hostname"]
        db.commit()
    except Exception:
        logger.exception("Network scan processing error")
    finally:
        db.close()


# ── Top Talkers ───────────────────────────────────────────────────────────────
@app.get("/api/top-talkers")
async def top_talkers(limit: int = 30, _=Depends(auth)):
    return talkers.top(limit)


# ── Threat Intel ──────────────────────────────────────────────────────────────
@app.get("/api/threat-intel")
async def ti_status(_=Depends(auth)):
    return threat_intel.status()


@app.get("/api/threat-intel/ips")
async def ti_ips(_=Depends(auth)):
    return sorted(threat_intel.malicious_ips)


@app.post("/api/threat-intel/refresh")
async def ti_refresh(_=Depends(auth)):
    threat_intel.last_refresh = None
    await threat_intel.refresh()
    return threat_intel.status()


# ── Network Devices ───────────────────────────────────────────────────────────
@app.get("/api/devices")
async def list_devices(db: Session = Depends(get_db), _=Depends(auth)):
    devs = db.query(NetworkDevice).order_by(NetworkDevice.last_seen.desc()).all()
    return [d.to_dict() for d in devs]


@app.put("/api/devices/{device_id}/acknowledge")
async def ack_device(device_id: int, db: Session = Depends(get_db), _=Depends(auth)):
    d = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404)
    d.known = True
    db.commit()
    return {"status": "ok"}


# ── Reverse DNS ───────────────────────────────────────────────────────────────
_rdns_cache: dict[str, tuple[str, float]] = {}
_RDNS_TTL = 3600


@app.get("/api/resolve/{ip}")
async def resolve_ip(ip: str, _=Depends(auth)):
    if not _re.match(r'^[\d.a-f:]+$', ip):
        raise HTTPException(status_code=400, detail="Invalid IP")

    now = datetime.utcnow().timestamp()
    if ip in _rdns_cache:
        hostname, ts = _rdns_cache[ip]
        if now - ts < _RDNS_TTL:
            return {"ip": ip, "hostname": hostname}

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _socket.gethostbyaddr, ip)
        hostname = result[0]
    except _socket.herror:
        hostname = "no PTR record"
    except Exception as e:
        hostname = f"lookup failed"

    _rdns_cache[ip] = (hostname, now)
    return {"ip": ip, "hostname": hostname}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
