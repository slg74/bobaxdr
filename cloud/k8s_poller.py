#!/usr/bin/env python3
"""
BobaxDR Kubernetes poller — monitors pods, services, and security posture
across all namespaces in the kind-kind cluster.

Usage:
  export BOBAXDR_API_KEY=<key>
  export BOBAXDR_SERVER=http://localhost:8000
  python3 cloud/k8s_poller.py
"""
import os
import sys
import time
import logging

import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("bobaxdr-k8s")

SERVER        = os.environ.get("BOBAXDR_SERVER", "http://localhost:8000").rstrip("/")
API_KEY       = os.environ.get("BOBAXDR_API_KEY", "")
K8S_CONTEXT   = os.environ.get("BOBAXDR_K8S_CONTEXT", "kind-kind")
POLL_INTERVAL = int(os.environ.get("BOBAXDR_K8S_INTERVAL", "60"))

# Namespaces to skip for new-pod alerts (system infra — still checked for security)
SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease",
             "local-path-storage", "metallb-system"}

SENSITIVE_HOST_PATHS = {"/etc", "/var/run/docker.sock", "/proc", "/sys", "/root"}

# Core system containers that legitimately require privileged mode
PRIVILEGED_WHITELIST = {"kube-proxy", "kube-apiserver", "etcd", "kube-scheduler",
                        "kube-controller-manager", "kindnet-cni", "install-cni"}

# Namespaces where observability agents legitimately need host access
MONITORING_NS = {"monitoring", "observability", "prometheus", "grafana", "metrics"}

# hostPath prefixes that are expected in kube-system (TLS certs, CNI config, kubeconfig)
SYSTEM_HOSTPATH_OK = {"/etc/kubernetes", "/etc/ca-certificates", "/etc/ssl/certs",
                      "/etc/cni", "/etc/containerd"}


def _pod_issues(pod) -> list[dict]:
    issues = []
    spec = pod.spec
    ns = pod.metadata.namespace

    host_ns_exempt = MONITORING_NS | SYSTEM_NS
    if spec.host_network and ns not in host_ns_exempt:
        issues.append({"severity": "high",
                       "description": "Pod using hostNetwork — shares host network stack"})
    if spec.host_pid and ns not in host_ns_exempt:
        issues.append({"severity": "high",
                       "description": "Pod using hostPID — can see all host processes"})

    for c in (spec.containers or []):
        sc = c.security_context
        if sc:
            if sc.privileged and c.name not in PRIVILEGED_WHITELIST:
                issues.append({"severity": "critical",
                               "description": f"Container '{c.name}' running privileged"})
            if sc.run_as_user == 0:
                issues.append({"severity": "medium",
                               "description": f"Container '{c.name}' running as root (UID 0)"})
            if sc.allow_privilege_escalation:
                issues.append({"severity": "medium",
                               "description": f"Container '{c.name}' allows privilege escalation"})

    for vol in (spec.volumes or []):
        if vol.host_path:
            path = vol.host_path.path
            if not any(path.startswith(s) for s in SENSITIVE_HOST_PATHS):
                continue
            if ns in MONITORING_NS and path in ("/sys", "/proc"):
                continue
            if ns in SYSTEM_NS and any(path.startswith(s) for s in SYSTEM_HOSTPATH_OK):
                continue
            issues.append({"severity": "high",
                           "description": f"Sensitive hostPath volume: {path}"})

    return issues


def _pod_status(pod) -> tuple[str, int]:
    """Returns (phase_string, restart_count)."""
    phase = pod.status.phase or "Unknown"
    restarts = 0
    for cs in (pod.status.container_statuses or []):
        restarts += cs.restart_count or 0
        if cs.state and cs.state.waiting:
            reason = cs.state.waiting.reason or ""
            if reason == "CrashLoopBackOff":
                phase = "CrashLoopBackOff"
    return phase, restarts


def discover_pods(v1) -> list[dict]:
    pods = []
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for pod in ret.items:
        ns   = pod.metadata.namespace
        name = pod.metadata.name
        phase, restarts = _pod_status(pod)
        images = [c.image for c in (pod.spec.containers or [])]
        issues = _pod_issues(pod)

        pods.append({
            "namespace": ns,
            "name":      name,
            "phase":     phase,
            "restarts":  restarts,
            "images":    images,
            "node":      pod.spec.node_name or "",
            "system":    ns in SYSTEM_NS,
            "issues":    issues,
        })
    return pods


def discover_services(v1) -> list[dict]:
    services = []
    ret = v1.list_service_for_all_namespaces(watch=False)
    for svc in ret.items:
        stype = svc.spec.type or "ClusterIP"
        exposed = stype in ("NodePort", "LoadBalancer")
        ports = []
        for p in (svc.spec.ports or []):
            port_str = f"{p.port}"
            if stype == "NodePort" and p.node_port:
                port_str += f"→{p.node_port}(nodeport)"
            ports.append(port_str)

        services.append({
            "namespace": svc.metadata.namespace,
            "name":      svc.metadata.name,
            "type":      stype,
            "exposed":   exposed,
            "ports":     ports,
            "cluster_ip": svc.spec.cluster_ip or "",
        })
    return services


def poll(session: requests.Session):
    try:
        config.load_kube_config(context=K8S_CONTEXT)
        v1 = client.CoreV1Api()

        pods     = discover_pods(v1)
        services = discover_services(v1)

        session.post(f"{SERVER}/api/events", json={
            "type":     "k8s_scan",
            "hostname": K8S_CONTEXT,
            "platform": "kubernetes",
            "context":  K8S_CONTEXT,
            "pods":     pods,
            "services": services,
        }, timeout=15)

        crash = sum(1 for p in pods if p["phase"] == "CrashLoopBackOff")
        issues = sum(len(p["issues"]) for p in pods)
        exposed = sum(1 for s in services if s["exposed"])
        logger.info(f"K8s: {len(pods)} pods, {crash} crashloop, "
                    f"{issues} security issue(s), {exposed} exposed service(s)")
    except Exception as e:
        logger.error(f"K8s poll error: {e}")


def main():
    if not API_KEY:
        logger.error("BOBAXDR_API_KEY not set"); sys.exit(1)
    session = requests.Session()
    session.headers["x-api-key"] = API_KEY
    logger.info(f"K8s poller starting — context: {K8S_CONTEXT}, interval: {POLL_INTERVAL}s")
    while True:
        poll(session)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
