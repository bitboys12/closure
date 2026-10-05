"""
CLOSURE Dynamic Enforcer Engine
Executes commands under strace observation, evaluates effect invariants in real-time,
and triggers instant process-tree termination upon boundary violations.
"""
import subprocess
import os
import signal
import sys
import datetime
from typing import Callable, Optional, List
from .models import (
    ApprovalSession,
    EffectBoundary,
    SessionStatus,
    ViolationCategory,
    ViolationEvent,
    SyscallEvent
)
from .telemetry_parser import TelemetryParser


class DynamicEnforcer:
    """
    Enforces Effect Boundaries in real-time on running subprocesses via strace telemetry.
    """

    def __init__(self, session: ApprovalSession, on_event_callback: Optional[Callable[[SyscallEvent], None]] = None):
        self.session = session
        self.boundary = session.boundary
        self.parser = TelemetryParser(base_dir=session.working_directory)
        self.on_event_callback = on_event_callback
        self.observed_events: List[SyscallEvent] = []

    def run(self) -> ApprovalSession:
        """
        Executes the session's command under strace, monitors syscalls, and enforces boundary.
        """
        command_str = self.session.command
        cwd = self.session.working_directory

        # Prepare strace wrapper command
        # Use /bin/sh for minimal, lightweight execution without bash interactive user queries
        strace_cmd = [
            "strace",
            "-f",
            "-s", "256",
            "-e", "trace=openat,execve,connect,open",
            "sh", "-c", command_str
        ]

        print(f"\n[CLOSURE Enforcer] Initiating monitored execution: {command_str}")
        print(f"[CLOSURE Enforcer] Working Directory: {cwd}")
        print(f"[CLOSURE Enforcer] Active Boundary: {len(self.boundary.allowed_read_paths)} read rules, {len(self.boundary.allowed_write_paths)} write rules, {len(self.boundary.deny_sensitive_paths)} deny rules")

        self.session.status = SessionStatus.RUNNING
        proc = None

        try:
            # Launch in new process group to allow killing entire process tree cleanly
            proc = subprocess.Popen(
                strace_cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None
            )

            # Strace outputs telemetry to stderr
            for raw_line in iter(proc.stderr.readline, ''):
                if not raw_line:
                    break

                event = self.parser.parse_line(raw_line)
                if not event:
                    continue

                self.observed_events.append(event)
                if self.on_event_callback:
                    self.on_event_callback(event)

                # Real-time Invariant Evaluation
                is_allowed, category, details = self.boundary.evaluate_event(event)

                if not is_allowed:
                    # VIOLATION DETECTED: Hard kill switch
                    print(f"\n" + "=" * 65)
                    print(f" [!] CLOSURE EFFECT BOUNDARY VIOLATION DETECTED")
                    print(f"     Category : {category.value if category else 'UNKNOWN'}")
                    print(f"     Syscall  : {event.syscall}")
                    print(f"     Target   : {event.target}")
                    print(f"     Reason   : {details}")
                    print(f"     Action   : Instant SIGKILL to process tree (PID: {proc.pid})")
                    print("=" * 65)

                    # Kill process group
                    self._kill_process_group(proc)

                    self.session.status = SessionStatus.TERMINATED_VIOLATION
                    self.session.violation = ViolationEvent(
                        syscall=event.syscall,
                        target=event.target,
                        category=category or ViolationCategory.FILESYSTEM_READ,
                        details=details or "Boundary violation",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
                    )
                    return self.session

            # Wait for clean process termination
            proc.wait(timeout=10)

            if proc.returncode == 0:
                self.session.status = SessionStatus.COMPLETED_ALLOWED
                print(f"[CLOSURE Enforcer] Execution completed within approved boundary: ALLOWED (Exit: 0)")
            else:
                self.session.status = SessionStatus.COMPLETED_ALLOWED
                print(f"[CLOSURE Enforcer] Execution exited with code {proc.returncode} (No security violation detected)")

        except subprocess.TimeoutExpired:
            print("[CLOSURE Enforcer] Execution timed out.")
            if proc:
                self._kill_process_group(proc)
        except Exception as e:
            print(f"[CLOSURE Enforcer] Runtime error during enforcement: {e}")
            if proc:
                self._kill_process_group(proc)
        finally:
            if proc and proc.poll() is None:
                self._kill_process_group(proc)

        return self.session

    def _kill_process_group(self, proc: subprocess.Popen):
        """Terminates the process and all its spawned children via process group kill."""
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass
