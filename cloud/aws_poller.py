#!/usr/bin/env python3
"""
BobaxDR AWS EC2 poller — discovers instances, analyzes security groups,
and reports to the BobaxDR server every 5 minutes.

Usage:
  export BOBAXDR_API_KEY=<key>
  export BOBAXDR_SERVER=http://localhost:8000
  python3 cloud/aws_poller.py

Credentials: uses ~/.aws/credentials (standard AWS CLI config)
"""
import os
import sys
import json
import time
import logging
import threading

import boto3
import requests
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("bobaxdr-aws")

SERVER       = os.environ.get("BOBAXDR_SERVER", "http://localhost:8000").rstrip("/")
API_KEY      = os.environ.get("BOBAXDR_API_KEY", "")
REGIONS      = os.environ.get("BOBAXDR_AWS_REGIONS", "us-east-1").split(",")
POLL_INTERVAL = int(os.environ.get("BOBAXDR_AWS_INTERVAL", "300"))

# Ports critical to expose publicly
CRITICAL_PORTS = {22: "SSH", 3389: "RDP", 5900: "VNC", 23: "Telnet", 5985: "WinRM"}


def _name_tag(tags: list) -> str:
    return next((t["Value"] for t in (tags or []) if t["Key"] == "Name"), "")


def analyze_security_groups(ec2, sg_ids: list) -> list:
    issues = []
    if not sg_ids:
        return issues
    try:
        resp = ec2.describe_security_groups(GroupIds=sg_ids)
        for sg in resp["SecurityGroups"]:
            for rule in sg.get("IpPermissions", []):
                proto     = rule.get("IpProtocol", "-1")
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort", 65535)

                open_world = any(
                    r.get("CidrIp") == "0.0.0.0/0"
                    for r in rule.get("IpRanges", [])
                ) or any(
                    r.get("CidrIpv6") == "::/0"
                    for r in rule.get("Ipv6Ranges", [])
                )
                if not open_world:
                    continue

                if proto == "-1":
                    port_desc = "all traffic"
                    severity  = "critical"
                elif from_port == to_port:
                    label     = CRITICAL_PORTS.get(from_port, "")
                    port_desc = f"port {from_port}" + (f" ({label})" if label else "")
                    severity  = "critical" if from_port in CRITICAL_PORTS else "high"
                else:
                    port_desc = f"ports {from_port}–{to_port}"
                    severity  = "high" if (to_port - from_port) > 99 else "medium"

                issues.append({
                    "sg_id":       sg["GroupId"],
                    "sg_name":     sg["GroupName"],
                    "protocol":    proto,
                    "from_port":   from_port,
                    "to_port":     to_port,
                    "port_desc":   port_desc,
                    "severity":    severity,
                    "description": (
                        f"{sg['GroupName']} ({sg['GroupId']}): "
                        f"{port_desc} open to 0.0.0.0/0"
                    ),
                })
    except ClientError as e:
        logger.warning(f"SG analysis error: {e}")
    return issues


def discover(region: str) -> list:
    ec2 = boto3.client("ec2", region_name=region)
    instances = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    state = inst["State"]["Name"]
                    if state == "terminated":
                        continue
                    sg_ids  = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                    lt      = inst.get("LaunchTime")
                    instances.append({
                        "instance_id":    inst["InstanceId"],
                        "name":           _name_tag(inst.get("Tags", [])),
                        "instance_type":  inst.get("InstanceType", ""),
                        "state":          state,
                        "public_ip":      inst.get("PublicIpAddress", ""),
                        "private_ip":     inst.get("PrivateIpAddress", ""),
                        "region":         region,
                        "ami_id":         inst.get("ImageId", ""),
                        "launch_time":    lt.isoformat() if lt else None,
                        "security_groups": [
                            {"id": sg["GroupId"], "name": sg["GroupName"]}
                            for sg in inst.get("SecurityGroups", [])
                        ],
                        "sg_issues": analyze_security_groups(ec2, sg_ids),
                    })
    except NoCredentialsError:
        logger.error("AWS credentials not found — configure ~/.aws/credentials")
    except ClientError as e:
        logger.error(f"AWS API error in {region}: {e}")
    return instances


def poll(session: requests.Session):
    for region in REGIONS:
        try:
            instances = discover(region.strip())
            session.post(f"{SERVER}/api/events", json={
                "type":      "aws_scan",
                "hostname":  f"aws-{region}",
                "platform":  "aws",
                "region":    region.strip(),
                "instances": instances,
            }, timeout=15)
            sg_issues = sum(len(i["sg_issues"]) for i in instances)
            logger.info(
                f"AWS {region}: {len(instances)} instances, "
                f"{sg_issues} security group issue(s)"
            )
        except Exception as e:
            logger.error(f"Poll error ({region}): {e}")


def main():
    if not API_KEY:
        logger.error("BOBAXDR_API_KEY not set")
        sys.exit(1)

    session = requests.Session()
    session.headers["x-api-key"] = API_KEY

    logger.info(f"AWS poller starting — regions: {REGIONS}, interval: {POLL_INTERVAL}s")
    logger.info(f"Reporting to {SERVER}")

    while True:
        poll(session)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
