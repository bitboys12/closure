#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " [CLOSURE] Sandbox & ptrace Verification Suite"
echo "=========================================================="

# 1. Verify Docker availability
if ! command -v docker >/dev/null 2>&1; then
  echo "[-] ERROR: docker binary not found in PATH."
  exit 1
fi

echo "[+] Docker binary detected: $(docker --version)"

# 2. Build Sandbox Image
echo "[*] Building CLOSURE sandbox container image..."
docker build -t closure-sandbox:latest .

# 3. Test strace capabilities inside container with SYS_PTRACE
echo "[*] Testing strace tracing inside container on Node.js process..."
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v "$(pwd):/workspace" \
  -w /workspace \
  closure-sandbox:latest \
  bash -c "strace -f -e trace=openat,execve node -e 'console.log(\"Tracing verified\");' 2>&1 | grep -E 'execve|openat'" > /tmp/strace_test.log || true

if grep -q "execve" /tmp/strace_test.log; then
  echo "[+] SUCCESS: strace intercepted syscalls successfully inside container!"
else
  echo "[-] WARNING: strace output did not contain expected syscalls."
  cat /tmp/strace_test.log
  exit 1
fi

# 4. Verify rogue package payload detection
echo "[*] Testing rogue package payload under strace tracing..."
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v "$(pwd):/workspace" \
  -w /workspace \
  closure-sandbox:latest \
  bash -c "strace -f -e trace=openat node packages/rogue-pkg/payload.js 2>&1 | grep '/etc/passwd'" > /tmp/payload_test.log || true

if grep -q "/etc/passwd" /tmp/payload_test.log; then
  echo "[+] SUCCESS: Target syscall 'openat(\"/etc/passwd\")' was cleanly intercepted!"
else
  echo "[-] WARNING: Failed to intercept /etc/passwd syscall in payload run."
  cat /tmp/payload_test.log
  exit 1
fi

echo "=========================================================="
echo " [✓] ALL SANDBOX VERIFICATION TESTS PASSED"
echo "=========================================================="
