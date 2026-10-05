#!/usr/bin/env python3
"""
CLOSURE Dynamic Enforcer Test Suite
Validates the Syscall Telemetry Parser and Invariant Enforcement Engine.
"""
import sys
import os
import json
import datetime

# Add repository root to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models import (
    ApprovalSession,
    EffectBoundary,
    SessionStatus,
    ViolationCategory
)
from core.enforcer import DynamicEnforcer


def run_tests():
    print("=" * 70)
    print(" [CLOSURE] ENFORCER & SYSCALL MONITOR INTEGRATION SUITE")
    print("=" * 70)

    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Load baseline boundary from contracts/mock_request.json
    contract_path = os.path.join(workspace_dir, "contracts", "mock_request.json")
    with open(contract_path, "r") as f:
        contract_data = json.load(f)

    b_data = contract_data["boundary"]
    boundary = EffectBoundary(
        allowed_read_paths=b_data["allowed_read_paths"],
        allowed_write_paths=b_data["allowed_write_paths"],
        allowed_network_hosts=b_data["allowed_network_hosts"],
        allowed_executables=b_data["allowed_executables"],
        deny_sensitive_paths=b_data["deny_sensitive_paths"]
    )

    # -------------------------------------------------------------
    # TEST CASE A: Benign Node.js Command Execution
    # -------------------------------------------------------------
    print("\n>>> TEST A: Benign Command Execution (Expect ALLOWED)")
    session_a = ApprovalSession(
        session_id="test-benign-001",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        agent_id="test-runner",
        command='node -e \'console.log("[Test App] Safe execution complete: " + (21 * 2));\'',
        working_directory=workspace_dir,
        boundary=boundary
    )

    enforcer_a = DynamicEnforcer(session_a)
    result_a = enforcer_a.run()

    print(f"[Result A] Final Status: {result_a.status.value}")
    assert result_a.status == SessionStatus.COMPLETED_ALLOWED, f"Expected COMPLETED_ALLOWED, got {result_a.status}"
    assert result_a.violation is None, "Expected no violation for benign command"
    print("✓ TEST A PASSED: Benign command allowed without interruption.\n")

    # -------------------------------------------------------------
    # TEST CASE B: Rogue Package Exploit (Unauthorized /etc/passwd Read)
    # -------------------------------------------------------------
    print(">>> TEST B: Rogue Package Exploit Lifecycle Hook (Expect BLOCKED)")
    session_b = ApprovalSession(
        session_id="test-rogue-002",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        agent_id="test-runner",
        command="node packages/rogue-pkg/payload.js",
        working_directory=workspace_dir,
        boundary=boundary
    )

    enforcer_b = DynamicEnforcer(session_b)
    result_b = enforcer_b.run()

    print(f"[Result B] Final Status: {result_b.status.value}")
    assert result_b.status == SessionStatus.TERMINATED_VIOLATION, f"Expected TERMINATED_VIOLATION, got {result_b.status}"
    assert result_b.violation is not None, "Expected a captured violation event"
    assert "/etc/passwd" in result_b.violation.target, f"Expected target /etc/passwd, got {result_b.violation.target}"
    assert result_b.violation.category == ViolationCategory.FILESYSTEM_READ, f"Expected FILESYSTEM_READ, got {result_b.violation.category}"
    print(f"✓ TEST B PASSED: Rogue exploit caught on {result_b.violation.syscall}('{result_b.violation.target}') and terminated instantaneously.\n")

    # -------------------------------------------------------------
    # TEST CASE C: Path Traversal Bypass Attempt (../../../etc/passwd)
    # -------------------------------------------------------------
    print(">>> TEST C: Path Traversal Evasion Attempt (Expect BLOCKED)")
    session_c = ApprovalSession(
        session_id="test-traversal-003",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        agent_id="test-runner",
        command="node -e 'try { require(\"fs\").readFileSync(\"./packages/rogue-pkg/../../../etc/passwd\"); } catch(e) {}'",
        working_directory=workspace_dir,
        boundary=boundary
    )

    enforcer_c = DynamicEnforcer(session_c)
    result_c = enforcer_c.run()

    print(f"[Result C] Final Status: {result_c.status.value}")
    assert result_c.status == SessionStatus.TERMINATED_VIOLATION, f"Expected TERMINATED_VIOLATION, got {result_c.status}"
    assert result_c.violation is not None, "Expected violation for path traversal attempt"
    assert result_c.violation.target == "/etc/passwd", f"Expected canonicalized /etc/passwd, got {result_c.violation.target}"
    print(f"✓ TEST C PASSED: Canonicalization neutralized path traversal. Caught: {result_c.violation.target}\n")

    print("=" * 70)
    print(" [✓] ALL ENFORCER & TELEMETRY TESTS PASSED (3/3)")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
