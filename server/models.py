from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from database import Base


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True)
    hostname = Column(String(255), unique=True, index=True)
    platform = Column(String(50))
    ip_address = Column(String(50))
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime)

    def to_dict(self):
        online = False
        if self.last_seen:
            delta = (datetime.utcnow() - self.last_seen).total_seconds()
            online = delta < 300
        return {
            "id": self.id,
            "hostname": self.hostname,
            "platform": self.platform,
            "ip_address": self.ip_address,
            "online": online,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
        }


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    event_type = Column(String(50), index=True)
    data = Column(Text)
    timestamp = Column(DateTime, default=_utcnow, index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), nullable=True)
    endpoint_hostname = Column(String(255))
    rule_name = Column(String(100))
    severity = Column(String(20), index=True)
    title = Column(String(500))
    description = Column(Text)
    indicator = Column(String(500))
    timestamp = Column(DateTime, default=_utcnow, index=True)
    acknowledged = Column(Boolean, default=False, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "endpoint_id": self.endpoint_id,
            "endpoint_hostname": self.endpoint_hostname,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "indicator": self.indicator,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "acknowledged": self.acknowledged,
        }
