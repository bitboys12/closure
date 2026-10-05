"""
CLOSURE Interactive FastAPI Gateway & WebSocket Telemetry Server
"""
import asyncio
import uuid
import datetime
import os
import sys
import json
from typing import Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.models import (
    ApprovalSession,
    EffectBoundary,
    SessionStatus,
    ViolationEvent,
    SyscallEvent
)
from core.enforcer import DynamicEnforcer
from core.boundary_generator import BoundaryGenerator

app = FastAPI(title="CLOSURE - Effect-Bound Approval Firewall API", version="1.0.0")

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active in-memory sessions
sessions: Dict[str, ApprovalSession] = {}
executor = ThreadPoolExecutor(max_workers=4)


class CommandRequest(BaseModel):
    command: str
    working_directory: Optional[str] = None
    agent_id: Optional[str] = "claude-code-agent-v1"
    custom_boundary: Optional[Dict[str, Any]] = None


@app.get("/api/presets")
def get_presets():
    """Returns curated demonstration presets for the hackathon showcase."""
    return [
        {
            "id": "rogue-pkg-lifecycle",
            "name": "Rogue npm Package (Supply-Chain Exploit)",
            "description": "Simulates npm install running a rogue postinstall hook that attempts to steal /etc/passwd.",
            "command": "node packages/rogue-pkg/payload.js",
            "expected_outcome": "BLOCKED (SIGKILL on /etc/passwd)"
        },
        {
            "id": "benign-calculation",
            "name": "Benign Math Utility Execution",
            "description": "Runs a harmless compute script that operates purely within approved bounds.",
            "command": "node -e 'console.log(\"[Safe Compute] Result:\", 42 * 100);'",
            "expected_outcome": "ALLOWED (Exit 0)"
        },
        {
            "id": "path-traversal-attack",
            "name": "Path Traversal Bypass Attempt",
            "description": "Attempts to evade boundaries via relative path traversal (../../../etc/passwd).",
            "command": "node -e 'try { require(\"fs\").readFileSync(\"./packages/rogue-pkg/../../../etc/passwd\"); } catch(e){}'",
            "expected_outcome": "BLOCKED (Neutralized by Canonicalization)"
        }
    ]


@app.post("/api/request")
def create_approval_request(req: CommandRequest):
    """
    Intercepts an agent command and generates an Effect Boundary for human approval.
    """
    session_id = f"req-{uuid.uuid4().hex[:12]}"
    cwd = req.working_directory or os.getcwd()

    if req.custom_boundary:
        b = req.custom_boundary
        boundary = EffectBoundary(
            allowed_read_paths=b.get("allowed_read_paths", []),
            allowed_write_paths=b.get("allowed_write_paths", []),
            allowed_network_hosts=b.get("allowed_network_hosts", []),
            allowed_executables=b.get("allowed_executables", []),
            deny_sensitive_paths=b.get("deny_sensitive_paths", [])
        )
    else:
        boundary = BoundaryGenerator.generate(req.command, cwd)

    session = ApprovalSession(
        session_id=session_id,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        agent_id=req.agent_id or "claude-code-agent-v1",
        command=req.command,
        working_directory=cwd,
        boundary=boundary,
        status=SessionStatus.PENDING_APPROVAL
    )

    sessions[session_id] = session

    return {
        "session_id": session.session_id,
        "timestamp": session.timestamp,
        "agent_id": session.agent_id,
        "command": session.command,
        "working_directory": session.working_directory,
        "status": session.status.value,
        "boundary": {
            "allowed_read_paths": boundary.allowed_read_paths,
            "allowed_write_paths": boundary.allowed_write_paths,
            "allowed_network_hosts": boundary.allowed_network_hosts,
            "allowed_executables": boundary.allowed_executables,
            "deny_sensitive_paths": boundary.deny_sensitive_paths
        }
    }


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    session = sessions[session_id]
    return {
        "session_id": session.session_id,
        "status": session.status.value,
        "command": session.command,
        "violation": {
            "syscall": session.violation.syscall,
            "target": session.violation.target,
            "category": session.violation.category.value,
            "details": session.violation.details,
            "timestamp": session.violation.timestamp
        } if session.violation else None
    }


@app.websocket("/ws/{session_id}")
async def websocket_telemetry(websocket: WebSocket, session_id: str):
    await websocket.accept()

    if session_id not in sessions:
        await websocket.send_json({"type": "ERROR", "message": "Invalid session_id"})
        await websocket.close()
        return

    session = sessions[session_id]
    loop = asyncio.get_running_loop()

    # Callback invoked in worker thread for each parsed syscall event
    def on_event(event: SyscallEvent):
        msg = {
            "type": "SYSCALL",
            "data": {
                "pid": event.pid,
                "syscall": event.syscall,
                "target": event.target,
                "is_write": event.is_write,
                "is_read": event.is_read,
                "is_exec": event.is_exec,
                "is_network": event.is_network,
                "status": "IN_BOUNDARY",
                "timestamp": event.timestamp,
                "raw": event.raw_line
            }
        }
        asyncio.run_coroutine_threadsafe(websocket.send_json(msg), loop)

    try:
        # Await client approval or rejection
        data = await websocket.receive_json()
        action = data.get("type", "").upper()

        if action == "REJECT":
            session.status = SessionStatus.REJECTED
            await websocket.send_json({
                "type": "FINISHED",
                "data": {
                    "status": "REJECTED",
                    "message": "Execution rejected by human operator."
                }
            })
            return

        elif action == "APPROVE":
            session.status = SessionStatus.APPROVED
            await websocket.send_json({"type": "STATUS_UPDATE", "data": {"status": "RUNNING"}})

            enforcer = DynamicEnforcer(session, on_event_callback=on_event)

            # Run enforcer in thread pool to prevent blocking asyncio loop
            updated_session = await loop.run_in_executor(executor, enforcer.run)

            # Check final outcome
            if updated_session.status == SessionStatus.TERMINATED_VIOLATION and updated_session.violation:
                await websocket.send_json({
                    "type": "VIOLATION",
                    "data": {
                        "category": updated_session.violation.category.value,
                        "target": updated_session.violation.target,
                        "syscall": updated_session.violation.syscall,
                        "details": updated_session.violation.details,
                        "action": "SIGKILL",
                        "timestamp": updated_session.violation.timestamp
                    }
                })

            await websocket.send_json({
                "type": "FINISHED",
                "data": {
                    "status": updated_session.status.value,
                    "violation": {
                        "category": updated_session.violation.category.value,
                        "target": updated_session.violation.target,
                        "syscall": updated_session.violation.syscall,
                        "details": updated_session.violation.details
                    } if updated_session.violation else None
                }
            })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "ERROR", "message": str(e)})
        except Exception:
            pass


# Mount Web Dashboard as static directory
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
if os.path.exists(dashboard_path):
    app.mount("/", StaticFiles(directory=dashboard_path, html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
