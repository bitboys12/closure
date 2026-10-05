"""
CLOSURE Core Domain Models, Syscall Events & Effect Boundary Evaluation
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple
import fnmatch
import os


class SessionStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    RUNNING = "RUNNING"
    COMPLETED_ALLOWED = "COMPLETED_ALLOWED"
    TERMINATED_VIOLATION = "TERMINATED_VIOLATION"


class ViolationCategory(str, Enum):
    FILESYSTEM_READ = "FILESYSTEM_READ"
    FILESYSTEM_WRITE = "FILESYSTEM_WRITE"
    NETWORK_OUTBOUND = "NETWORK_OUTBOUND"
    EXEC_UNAUTHORIZED = "EXEC_UNAUTHORIZED"


@dataclass
class SyscallEvent:
    pid: int
    syscall: str
    target: str
    is_write: bool = False
    is_read: bool = False
    is_network: bool = False
    is_exec: bool = False
    raw_line: str = ""
    timestamp: Optional[str] = None


@dataclass
class ViolationEvent:
    syscall: str
    target: str
    category: ViolationCategory
    details: str
    timestamp: str


@dataclass
class EffectBoundary:
    allowed_read_paths: List[str] = field(default_factory=list)
    allowed_write_paths: List[str] = field(default_factory=list)
    allowed_network_hosts: List[str] = field(default_factory=list)
    allowed_executables: List[str] = field(default_factory=list)
    deny_sensitive_paths: List[str] = field(default_factory=list)

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Canonicalize path to eliminate traversal bypasses like /app/../etc/passwd"""
        if not path or path == "<unknown>":
            return path
        try:
            return os.path.normpath(path)
        except Exception:
            return path

    def _matches_pattern(self, target_path: str, pattern: str) -> bool:
        norm_target = self._normalize_path(target_path)
        norm_pattern = self._normalize_path(pattern)

        # Glob match (e.g. /workspace/** or *.js)
        if fnmatch.fnmatch(norm_target, norm_pattern):
            return True

        # Directory prefix match (e.g. /workspace/demo_app/)
        prefix = norm_pattern.rstrip("*").rstrip("/")
        if prefix and (norm_target == prefix or norm_target.startswith(prefix + "/")):
            return True

        return False

    def is_read_allowed(self, path: str) -> bool:
        norm_path = self._normalize_path(path)
        # Check explicit blacklist first
        for pattern in self.deny_sensitive_paths:
            if self._matches_pattern(norm_path, pattern):
                return False

        # Check whitelist
        for pattern in self.allowed_read_paths:
            if self._matches_pattern(norm_path, pattern):
                return True
        return False

    def is_write_allowed(self, path: str) -> bool:
        norm_path = self._normalize_path(path)
        # Check explicit blacklist first
        for pattern in self.deny_sensitive_paths:
            if self._matches_pattern(norm_path, pattern):
                return False

        # Check whitelist
        for pattern in self.allowed_write_paths:
            if self._matches_pattern(norm_path, pattern):
                return True
        return False

    def is_exec_allowed(self, binary: str) -> bool:
        base_name = binary.split("/")[-1]
        for allowed in self.allowed_executables:
            if allowed == binary or allowed == base_name or fnmatch.fnmatch(binary, allowed):
                return True
        return False

    def is_network_allowed(self, host: str) -> bool:
        for allowed in self.allowed_network_hosts:
            if allowed == "*" or allowed == host or fnmatch.fnmatch(host, allowed):
                return True
        return False

    def evaluate_event(self, event: SyscallEvent) -> Tuple[bool, Optional[ViolationCategory], Optional[str]]:
        """
        Evaluates a SyscallEvent against the boundary rules.
        Returns: (is_allowed: bool, violation_category, details_reason)
        """
        # 1. Exec check
        if event.is_exec:
            if not self.is_exec_allowed(event.target):
                return False, ViolationCategory.EXEC_UNAUTHORIZED, f"Execution of binary '{event.target}' is outside approved executables"

        # 2. Write check
        if event.is_write:
            if not self.is_write_allowed(event.target):
                return False, ViolationCategory.FILESYSTEM_WRITE, f"Unauthorized file write access to '{event.target}'"

        # 3. Read check (only if not write)
        elif event.is_read:
            if not self.is_read_allowed(event.target):
                return False, ViolationCategory.FILESYSTEM_READ, f"Unauthorized file read access to '{event.target}'"

        # 4. Network check
        if event.is_network:
            if not self.is_network_allowed(event.target):
                return False, ViolationCategory.NETWORK_OUTBOUND, f"Unauthorized outbound connection to '{event.target}'"

        return True, None, None


@dataclass
class ApprovalSession:
    session_id: str
    timestamp: str
    agent_id: str
    command: str
    working_directory: str
    boundary: EffectBoundary
    status: SessionStatus = SessionStatus.PENDING_APPROVAL
    violation: Optional[ViolationEvent] = None
