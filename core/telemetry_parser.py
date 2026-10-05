"""
CLOSURE Telemetry Parser
Parses live strace stream into structured SyscallEvents with security canonicalization.
"""
import re
import os
import datetime
from typing import Optional
from .models import SyscallEvent


class TelemetryParser:
    """
    Streaming parser for strace lines generated with:
    strace -f -s 256 -e trace=openat,execve,connect,open
    """

    # Regex patterns for strace output variants:
    # 1. [pid 12345] syscall(...) = result
    # 2. 12345 syscall(...) = result
    # 3. syscall(...) = result
    PID_PREFIX_PATTERN = re.compile(r"^(?:\[pid\s+(\d+)\]|\s*(\d+))?\s*(.*)$")

    # Syscall extractors
    OPENAT_PATTERN = re.compile(r'^openat\(\s*(?:AT_FDCWD|\d+)\s*,\s*"([^"]+)"\s*,\s*([^,\)]+)(?:,\s*([^,\)]+))?\s*\)\s*=\s*(-?\d+)')
    OPEN_PATTERN = re.compile(r'^open\(\s*"([^"]+)"\s*,\s*([^,\)]+)(?:,\s*([^,\)]+))?\s*\)\s*=\s*(-?\d+)')
    EXECVE_PATTERN = re.compile(r'^execve\(\s*"([^"]+)"\s*,\s*\[([^\]]*)\]')
    CONNECT_INET_PATTERN = re.compile(r'connect\(\s*\d+\s*,\s*\{sa_family=AF_INET(?:6)?,\s*(?:sin_port|sin6_port)=htons\((\d+)\),\s*(?:sin_addr=inet_addr\("([^"]+)"\)|sin6_addr=inet_pton\([^,]+,\s*"([^"]+)"\))')

    WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.getcwd()

    def canonicalize_path(self, path: str) -> str:
        """
        Normalize and canonicalize file paths to prevent traversal evasion
        (e.g., /workspace/demo/../etc/passwd -> /etc/passwd).
        """
        if not path:
            return path
        try:
            # If relative, resolve against base_dir
            if not os.path.isabs(path):
                norm = os.path.normpath(os.path.join(self.base_dir, path))
            else:
                norm = os.path.normpath(path)
            return norm
        except Exception:
            return path

    def parse_line(self, line: str) -> Optional[SyscallEvent]:
        """
        Parses a single line of strace output into a SyscallEvent.
        Returns None if the line does not match an intercepted target syscall.
        """
        line = line.strip()
        if not line or line.startswith("+++") or line.startswith("---"):
            return None

        # Extract PID if present
        pid_match = self.PID_PREFIX_PATTERN.match(line)
        pid = 0
        syscall_content = line
        if pid_match:
            pid_str = pid_match.group(1) or pid_match.group(2)
            if pid_str:
                pid = int(pid_str)
            syscall_content = pid_match.group(3)

        timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Match openat()
        openat_match = self.OPENAT_PATTERN.match(syscall_content)
        if openat_match:
            raw_path = openat_match.group(1)
            flags_str = openat_match.group(2)
            target = self.canonicalize_path(raw_path)
            is_write = any(flag in flags_str for flag in self.WRITE_FLAGS)
            is_read = not is_write or "O_RDWR" in flags_str

            return SyscallEvent(
                pid=pid,
                syscall="openat",
                target=target,
                is_write=is_write,
                is_read=is_read,
                is_network=False,
                is_exec=False,
                raw_line=line,
                timestamp=timestamp_str
            )

        # 2. Match open() (legacy/fallback)
        open_match = self.OPEN_PATTERN.match(syscall_content)
        if open_match:
            raw_path = open_match.group(1)
            flags_str = open_match.group(2)
            target = self.canonicalize_path(raw_path)
            is_write = any(flag in flags_str for flag in self.WRITE_FLAGS)
            is_read = not is_write or "O_RDWR" in flags_str

            return SyscallEvent(
                pid=pid,
                syscall="open",
                target=target,
                is_write=is_write,
                is_read=is_read,
                is_network=False,
                is_exec=False,
                raw_line=line,
                timestamp=timestamp_str
            )

        # 3. Match execve()
        execve_match = self.EXECVE_PATTERN.match(syscall_content)
        if execve_match:
            binary_path = execve_match.group(1)
            target = self.canonicalize_path(binary_path)

            return SyscallEvent(
                pid=pid,
                syscall="execve",
                target=target,
                is_write=False,
                is_read=False,
                is_network=False,
                is_exec=True,
                raw_line=line,
                timestamp=timestamp_str
            )

        # 4. Match connect() (AF_INET / AF_INET6)
        connect_match = self.CONNECT_INET_PATTERN.search(syscall_content)
        if connect_match:
            port = connect_match.group(1)
            ip = connect_match.group(2) or connect_match.group(3) or "unknown"
            target = f"{ip}:{port}"

            return SyscallEvent(
                pid=pid,
                syscall="connect",
                target=target,
                is_write=False,
                is_read=False,
                is_network=True,
                is_exec=False,
                raw_line=line,
                timestamp=timestamp_str
            )

        return None
