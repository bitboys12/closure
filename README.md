# CLOSURE: Effect-Bound Approval Firewall

CLOSURE is an **Effect-Bound Approval Firewall** designed to solve the *Illusion of Control* in human-in-the-loop AI systems. Instead of prompting users to approve high-level commands whose full transitive blast radius is opaque (such as `npm install`), CLOSURE generates, displays, and enforces strict dynamic effect boundaries using deep kernel/syscall tracing (`strace`) and real-time interactive dashboards.

---

## 🔒 Key Features

1. **Pre-Execution Effect Boundary Generation (`core/boundary_generator.py`)**:
   - Computes explicit boundaries for file reads, file writes, network egress endpoints, and spawned child executables.
   - Formulates a deterministic boundary contract (`contracts/boundary.schema.json`).

2. **Real-Time Syscall Telemetry Parser (`core/telemetry_parser.py`)**:
   - Streams raw `strace` events (`openat`, `execve`, `connect`, etc.) in real time.
   - Canonicalizes filesystem paths (`realpath`) to neutralize path traversal bypasses.
   - Evaluates whether each operation is within the approved effect boundary.

3. **Active Process Interception & Enforcer Engine (`core/enforcer.py`)**:
   - Runs untrusted child processes under sandbox containment.
   - Instantly intercepts out-of-boundary syscalls and terminates offending processes before unauthorized disk writes or data exfiltration occur.

4. **Interactive WebSocket Gateway & Live Dashboard (`core/gateway.py` & `dashboard/`)**:
   - FastAPI gateway with WebSocket streaming (`/ws/{session_id}`).
   - Dark-mode real-time terminal & violation monitor visualizer.
   - Interactive human approval dialog with granular capability breakdown.

5. **Rogue Test Package (`packages/rogue-pkg/`)**:
   - Contains a simulated supply-chain attack payload in `postinstall` attempting unauthorized credential access (`~/.ssh/id_rsa`) and external network exfiltration (`attacker-c2.net:443`).

---

## 📂 Project Architecture

```
cyber/
├── contracts/
│   ├── boundary.schema.json      # JSON schema defining EffectBoundary & Telemetry contracts
│   └── mock_request.json         # Example boundary request payload
├── core/
│   ├── boundary_generator.py     # Command heuristic analyzer & boundary generator
│   ├── enforcer.py               # strace process runner & syscall enforcer
│   ├── gateway.py                # FastAPI HTTP & WebSocket interactive gateway
│   ├── models.py                 # Pydantic data models & status enums
│   └── telemetry_parser.py       # Regex streaming syscall parser
├── dashboard/
│   ├── index.html                # Real-time WebSocket visualizer & approval UI
│   ├── app.js                    # UI state management & event streamer
│   └── style.css                 # Dark-mode glassmorphic styling
├── packages/
│   └── rogue-pkg/                # Exploit demonstration package (supply chain payload)
│       ├── package.json
│       └── payload.js
├── scripts/
│   └── run_demo.sh               # Quickstart launcher
├── Dockerfile                    # Isolated containerized sandbox environment
└── docker-compose.yml            # Container orchestration with SYS_PTRACE capability
```

---

## 🚀 Quickstart

### 1. Build and Run via Docker Compose
```bash
docker compose up --build
```

### 2. Access the Dashboard
Open your browser at `http://localhost:8000`.

### 3. Run the Demonstration
1. Enter an untrusted installation command (e.g. `npm install ./packages/rogue-pkg`).
2. Review the generated Effect Boundary.
3. Approve execution and observe the live syscall stream.
4. Watch CLOSURE detect out-of-boundary access to `~/.ssh/id_rsa` and terminate the rogue child process.
