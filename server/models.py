import json as _json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, UniqueConstraint
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


class CloudInstance(Base):
    __tablename__ = "cloud_instances"

    id            = Column(Integer, primary_key=True)
    instance_id   = Column(String(50), unique=True, index=True)
    name          = Column(String(255))
    instance_type = Column(String(50))
    state         = Column(String(20), index=True)
    prev_state    = Column(String(20))
    public_ip     = Column(String(50))
    private_ip    = Column(String(50))
    region        = Column(String(20))
    ami_id        = Column(String(50))
    launch_time   = Column(DateTime)
    security_groups = Column(Text)  # JSON
    sg_issues     = Column(Text)    # JSON
    first_seen    = Column(DateTime, default=_utcnow)
    last_seen     = Column(DateTime)

    def to_dict(self):
        return {
            "id":            self.id,
            "instance_id":   self.instance_id,
            "name":          self.name,
            "instance_type": self.instance_type,
            "state":         self.state,
            "public_ip":     self.public_ip,
            "private_ip":    self.private_ip,
            "region":        self.region,
            "ami_id":        self.ami_id,
            "launch_time":   self.launch_time.isoformat() if self.launch_time else None,
            "security_groups": _json.loads(self.security_groups) if self.security_groups else [],
            "sg_issues":     _json.loads(self.sg_issues) if self.sg_issues else [],
            "first_seen":    self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":     self.last_seen.isoformat() if self.last_seen else None,
        }


class NetworkDevice(Base):
    __tablename__ = "network_devices"

    id = Column(Integer, primary_key=True)
    ip = Column(String(50), unique=True, index=True)
    mac = Column(String(50))
    hostname = Column(String(255))
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime)
    known = Column(Boolean, default=False)  # user-acknowledged as expected

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "known": self.known,
        }
