"""
CLOSURE Effect Boundary Generator
Generates structured security boundaries for intercepted AI agent commands.
"""
from typing import Optional
from .models import EffectBoundary


class BoundaryGenerator:
    """
    Synthesizes effect boundaries using deterministic rule heuristics
    for standard tools and packages.
    """

    @staticmethod
    def generate(command: str, working_dir: str = "/workspace") -> EffectBoundary:
        cmd_lower = command.strip().lower()

        # Common baseline system read paths needed by OS/glibc/Node
        base_reads = [
            f"{working_dir}/**",
            "/usr/**",
            "/lib/**",
            "/lib64/**",
            "/etc/**",
            "/dev/**",
            "/proc/**",
            "/sys/**",
            "/tmp/**"
        ]

        # Common baseline system write paths
        base_writes = [
            f"{working_dir}/**",
            "/dev/tty",
            "/dev/null",
            "/dev/pts/**",
            "/dev/stderr",
            "/dev/stdout",
            "/tmp/**"
        ]

        # Strict sensitive blacklist
        sensitive_denies = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/sudoers",
            "/root/.ssh/**",
            "/root/.aws/**",
            "/root/.gnupg/**",
            "/home/*/.ssh/**",
            "/proc/kcore"
        ]

        # Preset heuristics based on command type
        if "npm" in cmd_lower or "yarn" in cmd_lower or "pnpm" in cmd_lower:
            return EffectBoundary(
                allowed_read_paths=base_reads,
                allowed_write_paths=base_writes + [
                    f"{working_dir}/node_modules/**",
                    f"{working_dir}/package.json",
                    f"{working_dir}/package-lock.json",
                    "/root/.npm/**"
                ],
                allowed_network_hosts=["registry.npmjs.org", "registry.yarnpkg.com"],
                allowed_executables=["npm", "node", "sh", "bash", "git"],
                deny_sensitive_paths=sensitive_denies
            )

        elif "pip" in cmd_lower or "python" in cmd_lower:
            return EffectBoundary(
                allowed_read_paths=base_reads,
                allowed_write_paths=base_writes + [
                    "/root/.cache/pip/**",
                    "/usr/local/lib/python*/**"
                ],
                allowed_network_hosts=["pypi.org", "files.pythonhosted.org"],
                allowed_executables=["python", "python3", "pip", "pip3", "sh", "bash"],
                deny_sensitive_paths=sensitive_denies
            )

        elif "git" in cmd_lower:
            return EffectBoundary(
                allowed_read_paths=base_reads,
                allowed_write_paths=base_writes + [
                    f"{working_dir}/.git/**"
                ],
                allowed_network_hosts=["github.com", "gitlab.com", "bitbucket.org"],
                allowed_executables=["git", "ssh", "sh", "bash"],
                deny_sensitive_paths=sensitive_denies
            )

        # Default fallback boundary for generic commands
        return EffectBoundary(
            allowed_read_paths=base_reads,
            allowed_write_paths=base_writes,
            allowed_network_hosts=["*"],
            allowed_executables=["node", "python3", "sh", "bash"],
            deny_sensitive_paths=sensitive_denies
        )
