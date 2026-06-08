# BobaxDR — Home XDR

A home-use Extended Detection and Response (XDR) system that monitors your entire environment from a single dashboard — home network devices, endpoint processes and connections, AWS EC2 instances, Kubernetes pods, and Docker containers. Detects threats in real time and surfaces security misconfigurations across all layers.

**Monitors:**
- **Home network** — all devices via ARP scanning, new device alerts, ARP spoofing detection, DNS hijack detection, C2 beaconing, malicious IP/domain connections, port scans, crypto miners, suspicious processes
- **AWS EC2** — instance inventory, state changes, security group exposure (SSH/RDP open to 0.0.0.0/0)
- **Kubernetes** — pod inventory across all namespaces, CrashLoopBackOff detection, privileged pods, hostNetwork/hostPID, sensitive volume mounts, exposed NodePort/LoadBalancer services
- **Docker** — running containers, privileged containers, host network mode, sensitive path mounts, ports bound to 0.0.0.0

Compatible with any home internet provider (Spectrum, Google Fiber, AT&T U-verse, and others). Inspired by Palo Alto Cortex XDR.

![BobaxDR Dashboard](bobaxdr_ss.png)

---

## Changelog

### 2026-06-07
- **Startup scripts** — replaced monolithic `start.sh` with `server-start.sh`, `server-stop.sh`, `agent-start.sh`, `agent-stop.sh`. Server script auto-starts all pollers and writes PID files to `/tmp/`. Agent script auto-detects virtualenv and Python path (supports both macOS Python 3.12 and Linux venv layouts).
- **Pollers panel** — AWS, Docker, and Kubernetes pollers now appear in their own dashboard section; they no longer inflate the active-endpoint count.
- **TOR_RELAY_CONNECTION rule** — fires on any outbound connection to port 9001 (Tor OR) or 9030 (Tor directory). Severity is Critical when the process is unnamed/unknown, High otherwise. PID and connection metadata are captured in `raw_data`.
- **Alert Detail button** — alerts that capture process context show a Detail button that opens a modal with PID, process name, remote IP/port, connection status, and detection timestamp.
- **parsecd added to benign list** — Apple's Siri/Spotlight/Safari Suggestions daemon was generating false-positive C2 beaconing alerts; suppressed at the detection layer.
- **API key hardening** — `.api_key` is `chmod 600` on every server start.
- **Git history cleaned** — `bobaxdr.db` permanently removed from repository history via `git-filter-repo`.

---

## Architecture

```
bobaxdr/
├── server/                  # Central server (run on always-on Mac)
│   ├── main.py              # FastAPI app, event ingestion, REST API
│   ├── database.py          # SQLite via SQLAlchemy
│   ├── models.py            # Endpoint, Event, Alert models
│   ├── detection/
│   │   ├── engine.py        # Detection rule engine
│   │   └── threat_intel.py  # Live threat feed downloader
│   └── static/
│       └── index.html       # Dark-mode dashboard UI
├── agent/                   # Endpoint agent (runs on every device)
│   ├── agent.py             # Main loop — collects and reports data
│   ├── process_monitor.py   # Running processes via psutil
│   └── network_monitor.py   # Active connections per process
├── cloud/                   # Cloud & container pollers
│   ├── aws_poller.py        # EC2 inventory + security group checks
│   ├── docker_poller.py     # Running containers, privileged flags
│   └── k8s_poller.py        # Pod inventory, CrashLoopBackOff, hostNetwork
├── sensor/
│   └── sensor.py            # Network sensor (packet capture or fallback)
├── server-start.sh          # Start server + all pollers (writes PID files)
├── server-stop.sh           # Stop server + all pollers
├── agent-start.sh           # Start agent (auto-detects venv, Python path)
├── agent-stop.sh            # Stop agent
├── install.sh               # Dependency installer
├── requirements-server.txt
├── requirements-agent.txt
└── requirements-sensor.txt
```

---

## Quick Start

### 1. Install

```bash
bash install.sh
```

### 2. Start the server (and pollers)

```bash
bash server-start.sh
```

This starts the FastAPI server, then waits for the API key to be generated and auto-starts the AWS, Docker, and Kubernetes pollers. PID files are written to `/tmp/bobaxdr-*.pid`; logs go to `/tmp/bobaxdr-*.log`. The dashboard opens at **http://localhost:8000**.

To stop everything cleanly:

```bash
bash server-stop.sh
```

### 3. Start the agent on this machine

```bash
bash agent-start.sh
```

The script auto-detects a virtualenv and the correct Python path. It reads the API key from `.api_key` (or `$BOBAXDR_API_KEY` if set) and defaults `BOBAXDR_SERVER` to `http://localhost:8000`. Stop it with:

```bash
bash agent-stop.sh
```

### 4. Add more devices

Copy the API key from `.api_key` in the project root, then follow the steps for each platform below.

---

## Installing the Agent

The agent runs on macOS, Windows, and Linux. It reports running processes and active network connections to the server every 10–30 seconds.

### macOS (remote)

```bash
# Copy agent files + start/stop scripts
scp agent/agent.py agent/process_monitor.py agent/network_monitor.py \
    agent-start.sh agent-stop.sh \
    user@<target-ip>:~/bobaxdr-agent/

# On the target Mac
cd ~/bobaxdr-agent
/Library/Frameworks/Python.framework/Versions/3.12/bin/pip3 install psutil requests
export BOBAXDR_API_KEY=<key>
export BOBAXDR_SERVER=http://<server-ip>:8000
bash agent-start.sh
```

> The script auto-selects the Python 3.12 framework install when present, falling back to system `python3`. The Xcode-bundled Python 3.9 at `/usr/bin/python3` will not work correctly.

### Linux (Kali, Ubuntu, Debian)

Modern Debian-based distros block system-wide pip installs. `agent-start.sh` handles venv detection automatically:

```bash
# Copy agent files + start/stop scripts
scp agent/agent.py agent/process_monitor.py agent/network_monitor.py \
    agent-start.sh agent-stop.sh \
    user@<target-ip>:~/bobaxdr-agent/

# On the target Linux machine — create the venv once
cd ~/bobaxdr-agent
python3 -m venv venv
source venv/bin/activate
pip install psutil requests

# Then start (re-activates venv automatically)
export BOBAXDR_API_KEY=<key>
export BOBAXDR_SERVER=http://<server-ip>:8000
bash agent-start.sh
```

### Windows

```powershell
# Copy agent files to C:\bobaxdr-agent\ then open PowerShell as Administrator
cd C:\bobaxdr-agent
pip install psutil requests

$env:BOBAXDR_API_KEY = "<key>"
$env:BOBAXDR_SERVER  = "http://<server-ip>:8000"
python agent.py
```

For best visibility on Windows, run as Administrator — this allows psutil to see connections from all processes, not just the current user.

### Verify the agent connected

After starting the agent, check the **Endpoints** panel in the dashboard. The device should appear as online within 30 seconds. You can also check from the server machine:

```bash
curl -s -H "x-api-key: $(cat .api_key)" http://localhost:8000/api/endpoints
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `BOBAXDR_API_KEY` | *(required)* | Key printed on first server start, saved to `.api_key` |
| `BOBAXDR_SERVER` | `http://localhost:8000` | URL of the BobaxDR server |
| `BOBAXDR_PROC_INTERVAL` | `30` | Seconds between process snapshots |
| `BOBAXDR_NET_INTERVAL` | `10` | Seconds between network connection snapshots |

---

### 5. Enable full network sensor (optional, requires sudo)

For DNS query monitoring and inbound port scan detection via packet capture:

```bash
sudo BOBAXDR_API_KEY=$BOBAXDR_API_KEY \
     BOBAXDR_SERVER=$BOBAXDR_SERVER \
     python3 sensor/sensor.py
```

Without sudo the sensor falls back to connection-level monitoring and still does DNS hijack detection.

---

## Dashboard

The web dashboard at **http://localhost:8000** shows:

- **Active alerts** with severity badges (Critical / High / Medium / Low)
  - **Detail button** — alerts that capture process context (e.g. `TOR_RELAY_CONNECTION`) show a Detail button that opens a modal with PID, process name, remote IP/port, connection status, and detection timestamp
  - Acknowledge button clears resolved findings; deduplication suppresses re-alerting for 10 minutes
- **Endpoints** — real agents (online/offline, platform, IP, last seen) shown separately from cloud/container pollers
- **Pollers** — AWS, Docker, and Kubernetes pollers appear in their own panel so they don't inflate the active-endpoint count
- **Threat intelligence status** — how many malicious IPs and domains are loaded
- Filter alerts by severity
- Auto-refreshes every 15 seconds

---

## Detection Rules

| Rule | Severity | How it fires |
|---|---|---|
| `CRYPTO_MINER` | Critical | Process name matches xmrig, cgminer, lolminer, and 20+ known miners |
| `CRYPTO_MINER_HEURISTIC` | High | Process using >85% CPU while connected to a mining pool port |
| `MALICIOUS_IP_CONNECTION` | Critical | Outbound connection to a Feodo Tracker C2 IP |
| `MALICIOUS_DOMAIN_DNS` | High | DNS query for a domain in the URLhaus blocklist |
| `C2_BEACONING` | High | Process connecting to the same external IP at statistically regular intervals |
| `PORT_SCAN_INBOUND` | High | 10+ TCP SYN packets from the same external IP to different ports within 60s |
| `PORT_SCAN_OUTBOUND` | Medium | A single process hitting 20+ unique external targets in one reporting interval |
| `DNS_TUNNELING` | Medium | DNS query sent to a non-standard port (not 53 / 853 / 5353) |
| `SUSPICIOUS_DNS_SERVER` | Medium | DNS routed to an unrecognized external server (trusted: Spectrum, Google Fiber, AT&T U-verse, Google Public DNS, Cloudflare, Quad9, OpenDNS) |
| `TOR_RELAY_CONNECTION` | Critical / High | Outbound connection to a known Tor OR port (9001) or directory port (9030). Escalates to Critical when the connecting process is unnamed/unknown — a named process connecting to Tor is High |
| `SUSPICIOUS_PROCESS_PATH` | High | Executable running from /tmp, Downloads, AppData Temp, or /dev/shm |

Alerts are deduplicated — the same rule + indicator on the same endpoint won't re-fire within 10 minutes.

Alerts with process context (PID, connection details) store a JSON blob in the `raw_data` field and show a **Detail** button in the dashboard.

---

## Threat Intelligence

Feeds are downloaded on startup and refreshed every 4 hours:

| Feed | Source | Content |
|---|---|---|
| Feodo Tracker | abuse.ch | Known botnet C2 IP addresses |
| URLhaus | abuse.ch | Malicious domains and URLs |

The sensor also maintains a DNS baseline at startup and alerts if a known domain starts resolving to an unexpected IP range (DNS hijack detection).

### What the Feodo C2 IPs actually are

The IPs in the Feodo blocklist are confirmed **botnet command-and-control servers** — machines that infected computers phone home to for instructions. They appear in the dashboard's Threat Intelligence panel as the watchlist. They are **not on your network**; BobaxDR watches for any local device that tries to connect to one and fires a Critical alert if it does.

The blocklist is dominated by two malware families:

**Emotet** — one of the most destructive banking trojans on record. Spreads via malicious email attachments, steals credentials, and is frequently used to drop ransomware. Was largely dismantled by a coordinated law enforcement takedown in 2021 but has resurfaced in waves since.

**QakBot** (QBot / Quakbot) — a banking trojan that steals credentials and browser data and acts as a loader for ransomware (notably Black Basta). The FBI disrupted its infrastructure in August 2023 ("Operation Duck Hunt"), but operators rebuilt and it remains active. QakBot C2s commonly run on port 443 to blend in with normal HTTPS traffic, hosted on cloud providers like AWS and DigitalOcean to avoid IP-based blocking.

The typical C2 hosting pattern — rented VPS nodes on AWS, DigitalOcean, or Sakura Internet, no reverse DNS (PTR) record set — is intentional. Legitimate services almost always configure PTR records; the absence of one on a server receiving regular connections is a red flag. Operators rent these servers cheaply, use them briefly, and abandon them when they get blocked, which is why the Feodo list contains a mix of `online` and `offline` entries.

---

## Configuration

All settings are via environment variables:

### Server

| Variable | Default | Description |
|---|---|---|
| `BOBAXDR_DB` | `bobaxdr.db` | Path to the SQLite database |

### Agent

| Variable | Default | Description |
|---|---|---|
| `BOBAXDR_SERVER` | `http://localhost:8000` | Server URL |
| `BOBAXDR_API_KEY` | *(required)* | API key from server startup |
| `BOBAXDR_PROC_INTERVAL` | `30` | Seconds between process snapshots |
| `BOBAXDR_NET_INTERVAL` | `10` | Seconds between network connection snapshots |

The API key is auto-generated on first server start and saved to `.api_key` in the project root.

---

## Requirements

**Python 3.10+** on all components.

On macOS, use the full python.org Python 3.12 install rather than the Xcode bundled Python:
```bash
/Library/Frameworks/Python.framework/Versions/3.12/bin/python3
```

**Server:** `fastapi uvicorn sqlalchemy aiohttp certifi`  
**Agent:** `psutil requests`  
**Sensor:** `scapy psutil requests dnspython` (scapy optional — fallback runs without it)

---

## How to Block an IP (macOS)

If BobaxDR fires a **Critical** alert for a `MALICIOUS_IP_CONNECTION` and you've confirmed it's not a false positive, block the IP using macOS's built-in `pf` packet filter.

### Temporary block (until reboot)

```bash
echo "block drop quick from any to <IP>" | sudo pfctl -ef -
```

### Permanent block

1. Open `/etc/pf.conf` in a text editor (requires sudo):

```bash
sudo nano /etc/pf.conf
```

2. Add this line near the top, after any existing `block` rules:

```
block drop quick from any to <IP>
```

3. Reload the ruleset:

```bash
sudo pfctl -f /etc/pf.conf
sudo pfctl -e   # enable pf if it isn't already running
```

4. Verify the rule is active:

```bash
sudo pfctl -sr | grep <IP>
```

### Block multiple IPs with a table (cleaner for a list)

```bash
# Create a persistent blocklist file
sudo nano /etc/pf-blocklist.conf
```

Add one IP per line:
```
1.2.3.4
5.6.7.8
```

Then in `/etc/pf.conf`, add:
```
table <blocklist> persist file "/etc/pf-blocklist.conf"
block drop quick from any to <blocklist>
block drop quick from <blocklist> to any
```

Reload with `sudo pfctl -f /etc/pf.conf`. To add new IPs later without a full reload:
```bash
sudo pfctl -t blocklist -T add <IP>
```

### Before you block

Check whether the alert is a false positive first:
- Click the IP in the **Top Talkers** tab to resolve it — legitimate services (Microsoft, Google, Apple, GitHub) almost always have a PTR record
- Check which process is making the connection in the **Events Processed** modal
- Well-known vendor clouds (Azure `20.x`, AWS `34.x`/`52.x`, Google `142.250.x`) are usually benign even without a PTR record

Real indicators worth blocking: unknown process + no PTR record + IP in Feodo/URLhaus blocklist + port 4444/8080/9001.

---

## Hardening EC2 Security Groups

BobaxDR fires `EC2_SG_EXPOSED` alerts when an instance has inbound rules open to `0.0.0.0/0`. Here's how to remediate each finding.

### Lock SSH (port 22) to your home IP only

The most common critical finding. Leaving SSH open to the world exposes the instance to credential brute-force and exploitation of SSH vulnerabilities.

```bash
# 1. Remove the open rule
aws ec2 revoke-security-group-ingress --region us-east-1 \
    --group-id <sg-id> \
    --protocol tcp --port 22 --cidr 0.0.0.0/0

# 2. Add your current home IP (force IPv4 with -4)
aws ec2 authorize-security-group-ingress --region us-east-1 \
    --group-id <sg-id> \
    --protocol tcp --port 22 --cidr $(curl -s -4 ifconfig.me)/32
```

> **Note:** Most home ISPs (Spectrum, Google Fiber, AT&T U-verse) assign dynamic IPs. If your home IP changes you'll lose SSH access and need to update the rule. See the Session Manager section below for a more permanent fix.

### Lock RDP (port 3389) to your home IP only

Same approach as SSH — RDP exposed to the internet is a Critical finding:

```bash
aws ec2 revoke-security-group-ingress --region us-east-1 \
    --group-id <sg-id> \
    --protocol tcp --port 3389 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress --region us-east-1 \
    --group-id <sg-id> \
    --protocol tcp --port 3389 --cidr $(curl -s -4 ifconfig.me)/32
```

### Remove all-traffic rules

If a security group has a rule allowing all protocols/ports to `0.0.0.0/0`:

```bash
aws ec2 revoke-security-group-ingress --region us-east-1 \
    --group-id <sg-id> \
    --protocol -1 --cidr 0.0.0.0/0
```

### Port 80/443 open to world (intentional web servers)

High-severity but expected for public-facing web servers. If intentional, acknowledge the alert in BobaxDR — it will suppress re-alerting for 24 hours. If the instance is not meant to serve web traffic, remove the rule:

```bash
aws ec2 revoke-security-group-ingress --region us-east-1 \
    --group-id <sg-id> \
    --protocol tcp --port 80 --cidr 0.0.0.0/0
```

### Avoid the dynamic IP problem — use AWS Session Manager

AWS Systems Manager Session Manager lets you SSH into instances through the AWS console or CLI without any inbound security group rules at all. No port 22 needed:

```bash
# Install the Session Manager plugin (macOS)
brew install --cask session-manager-plugin

# Connect to an instance (no SSH key or open port required)
aws ssm start-session --region us-east-1 --target <instance-id>
```

Requirements: the instance needs the SSM Agent running (pre-installed on Amazon Linux 2/2023 and Ubuntu 20.04+ AMIs) and an IAM role with `AmazonSSMManagedInstanceCore` attached.

### Verify the fix

After updating rules, trigger a rescan from the BobaxDR project root:

```bash
BOBAXDR_API_KEY=$(cat .api_key) BOBAXDR_SERVER=http://localhost:8000 \
    python3 cloud/aws_poller.py
```

The instance's SG issue pill in the dashboard should clear within seconds of the scan completing.
