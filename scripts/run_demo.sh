#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " [CLOSURE] Effect-Bound Approval Firewall — Live Demo"
echo "=========================================================="

# 1. Build or update Docker container
echo "[*] Building CLOSURE Sandbox & Gateway container..."
docker build -t closure-sandbox:latest .

# 2. Stop any existing demo container
docker rm -f closure_live_gateway >/dev/null 2>&1 || true

echo "[*] Launching CLOSURE Sandbox Gateway & Real-Time Dashboard..."
docker run -d \
  --name closure_live_gateway \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -p 8000:8000 \
  -v "$(pwd):/workspace" \
  -w /workspace \
  closure-sandbox:latest \
  python3 core/gateway.py

echo ""
echo "=========================================================="
echo " [✓] CLOSURE IS RUNNING & READY FOR LIVE DEMONSTRATIONS"
echo "=========================================================="
echo ""
echo "  👉 Open Web Visualizer: http://localhost:8000"
echo ""
echo "  Featured Scenarios to Demo:"
echo "   1. Rogue npm Package Exploit  -> Intercepts postinstall /etc/passwd exfiltration"
echo "   2. Benign Math Calculation    -> Normal compute running safely in-bounds"
echo "   3. Path Traversal Bypass      -> Neutralizes ../../../etc/passwd evasion"
echo ""
echo "  To view live container logs:  docker logs -f closure_live_gateway"
echo "  To stop the demo:             docker stop closure_live_gateway"
echo "=========================================================="
