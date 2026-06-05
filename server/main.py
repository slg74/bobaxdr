import os
import sys
import secrets
import logging
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
from models import Endpoint, Event, Alert
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


@app.delete("/api/alerts/acknowledged")
async def clear_acknowledged(db: Session = Depends(get_db), _=Depends(auth)):
    n = db.query(Alert).filter(Alert.acknowledged == True).delete()
    db.commit()
    return {"deleted": n}


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/api/endpoints")
async def list_endpoints(db: Session = Depends(get_db), _=Depends(auth)):
    return [e.to_dict() for e in db.query(Endpoint).all()]


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


# ── Threat Intel ──────────────────────────────────────────────────────────────
@app.get("/api/threat-intel")
async def ti_status(_=Depends(auth)):
    return threat_intel.status()


@app.post("/api/threat-intel/refresh")
async def ti_refresh(_=Depends(auth)):
    threat_intel.last_refresh = None
    await threat_intel.refresh()
    return threat_intel.status()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
