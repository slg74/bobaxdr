#!/usr/bin/env python3
"""
BobaxDR Docker container poller.
Discovers running containers, checks for security misconfigurations,
and reports to the BobaxDR server every 60 seconds.

Usage:
  export BOBAXDR_API_KEY=<key>
  export BOBAXDR_SERVER=http://localhost:8000
  python3 cloud/docker_poller.py
"""
import os
import sys
import time
import logging

import docker
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("bobaxdr-docker")

SERVER        = os.environ.get("BOBAXDR_SERVER", "http://localhost:8000").rstrip("/")
API_KEY       = os.environ.get("BOBAXDR_API_KEY", "")
POLL_INTERVAL = int(os.environ.get("BOBAXDR_DOCKER_INTERVAL", "60"))

# Images that are expected infrastructure — skip security checks but still inventory
INFRA_IMAGES = {"kindest/node", "docker/desktop-cloud-provider-kind",
                "docker/desktop-containerd-registry-mirror", "envoyproxy/envoy"}

SENSITIVE_PATHS = {"/etc", "/var/run/docker.sock", "/proc", "/sys",
                   "/root", "/run/containerd"}


def _is_infra(image: str) -> bool:
    return any(image.startswith(i) for i in INFRA_IMAGES)


def _check_container(c) -> list[dict]:
    issues = []
    attrs = c.attrs
    hc = attrs.get("HostConfig", {})

    if hc.get("Privileged"):
        issues.append({"severity": "critical", "description": "Container running with --privileged"})

    if hc.get("NetworkMode") == "host":
        issues.append({"severity": "high", "description": "Container using host network (--net=host)"})

    if hc.get("PidMode") == "host":
        issues.append({"severity": "high", "description": "Container sharing host PID namespace"})

    for mount in attrs.get("Mounts", []):
        src = mount.get("Source", "")
        if any(src.startswith(p) for p in SENSITIVE_PATHS):
            issues.append({"severity": "high",
                           "description": f"Sensitive host path mounted: {src}"})

    # Ports bound to all interfaces
    for container_port, bindings in (hc.get("PortBindings") or {}).items():
        for b in (bindings or []):
            host_ip = b.get("HostIp", "")
            host_port = b.get("HostPort", "")
            if host_ip in ("0.0.0.0", ""):
                issues.append({"severity": "medium",
                               "description": f"Port {host_port} bound to 0.0.0.0 (→ {container_port})"})

    return issues


def discover() -> list[dict]:
    client = docker.from_env()
    containers = []
    for c in client.containers.list(all=False):
        image = c.image.tags[0] if c.image.tags else c.image.short_id
        infra = _is_infra(image)
        issues = [] if infra else _check_container(c)

        ports = []
        for container_port, bindings in (c.ports or {}).items():
            for b in (bindings or []):
                ports.append(f"{b.get('HostIp','0.0.0.0')}:{b.get('HostPort','')}→{container_port}")

        containers.append({
            "container_id": c.short_id,
            "name":         c.name,
            "image":        image,
            "status":       c.status,
            "ports":        ports,
            "infra":        infra,
            "issues":       issues,
        })
    return containers


def poll(session: requests.Session):
    try:
        containers = discover()
        session.post(f"{SERVER}/api/events", json={
            "type":       "docker_scan",
            "hostname":   "docker-desktop",
            "platform":   "docker",
            "containers": containers,
        }, timeout=10)
        issues_total = sum(len(c["issues"]) for c in containers)
        logger.info(f"Docker: {len(containers)} containers, {issues_total} issue(s)")
    except docker.errors.DockerException as e:
        logger.error(f"Docker error: {e}")
    except Exception as e:
        logger.error(f"Poll error: {e}")


def main():
    if not API_KEY:
        logger.error("BOBAXDR_API_KEY not set"); sys.exit(1)
    session = requests.Session()
    session.headers["x-api-key"] = API_KEY
    logger.info(f"Docker poller starting — interval: {POLL_INTERVAL}s")
    while True:
        poll(session)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
