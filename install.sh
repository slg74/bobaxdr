#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "BobaxDR — Installing dependencies"
echo ""

# Server
echo "→ Server dependencies"
pip3 install -q -r requirements-server.txt
echo "  ✓ fastapi, uvicorn, sqlalchemy, aiohttp"

# Agent
echo "→ Agent dependencies"
pip3 install -q -r requirements-agent.txt
echo "  ✓ psutil, requests"

# Sensor (scapy is optional — packet capture needs root)
echo "→ Sensor dependencies"
pip3 install -q -r requirements-sensor.txt 2>/dev/null || echo "  ! scapy install failed — sensor will run in fallback mode"
echo "  ✓ done"

echo ""
echo "═══════════════════════════════════════════════════════"
echo " BobaxDR installed."
echo ""
echo " 1. Start the server (run once, always-on machine):"
echo "      cd server && python3 main.py"
echo ""
echo " 2. Copy the API key printed on first start, then on"
echo "    each device you want to monitor:"
echo "      export BOBAXDR_SERVER=http://<server-ip>:8000"
echo "      export BOBAXDR_API_KEY=<key>"
echo "      cd agent && python3 agent.py"
echo ""
echo " 3. (Optional) Full network sensor with packet capture:"
echo "      sudo BOBAXDR_API_KEY=\$BOBAXDR_API_KEY \\"
echo "           BOBAXDR_SERVER=\$BOBAXDR_SERVER \\"
echo "           python3 sensor/sensor.py"
echo ""
echo " 4. Open dashboard: http://localhost:8000"
echo "═══════════════════════════════════════════════════════"
