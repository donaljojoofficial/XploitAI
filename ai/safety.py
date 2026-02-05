"""
AI Command Safety Filter — XploitAI

Responsibilities:
- Validate AI-generated commands against safety rules.
- Enforce whitelisting of allowed tools.
- Block dangerous patterns and characters.

This module acts as a sandbox guardrail before execution.
"""

import logging
import ipaddress
import re
from typing import Set

logger = logging.getLogger(__name__)


class CommandSafety:
    """
    Safety filter for shell commands.
    """

    # Whitelist of allowed binaries for Phase 1/2
    ALLOWED_TOOLS: Set[str] = {
        "echo",
        "nmap",
        "whois",
        "nslookup",
        "nc",
        "netcat",
        "ping",
        "cat",
        "grep",
    }

    # Tools that require network scope validation
    NETWORK_TOOLS: Set[str] = {
        "nmap", "whois", "nslookup", "nc", "netcat", "ping"
    }

    # Allowed Network Scopes (RFC1918 + Loopback)
    ALLOWED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    ALLOWED_DOMAINS = {".local", ".lab", ".test", ".lan", "localhost"}

    # Blacklist of dangerous patterns
    FORBIDDEN_PATTERNS = [
        r"rm\s+-rf",        # Recursive delete
        r">\s*/etc/",       # System file overwrite
        r">\s*/dev/",       # Device write
        r":(){ :|:& };:",   # Fork bomb
        r"chmod\s+777",     # Permissive chmod
        r"wget",            # Downloaders (unless whitelisted)
        r"curl",
        r"bash\s+-i",       # Interactive shells
        r"nc\s+-e",         # Reverse shells (unless explicitly allowed for exploit simulation)
    ]

    def validate(self, command: str) -> tuple[bool, str]:
        """
        Check if a command is safe to execute.

        Args:
            command: The shell command string.

        Returns:
            (bool, str): (True, "OK") if safe, (False, Reason) if unsafe.
        """
        if not command or not command.strip():
            return False, "Command is empty."

        # 1. Check Forbidden Patterns
        for pattern in self.FORBIDDEN_PATTERNS:
            if re.search(pattern, command):
                return False, f"Command matches forbidden pattern: {pattern}"

        # 2. Check Tool Whitelist
        # Split by common operators to check each subcommand
        # Operators: ; | & && ||
        subcommands = re.split(r'[;&|]+', command)

        for subcmd in subcommands:
            subcmd = subcmd.strip()
            if not subcmd:
                continue

            # Extract binary name (first token)
            tokens = subcmd.split()
            if not tokens:
                continue

            binary = tokens[0]
            # Handle paths like /usr/bin/nmap
            binary_name = binary.split('/')[-1]

            if binary_name not in self.ALLOWED_TOOLS:
                return False, f"Binary '{binary_name}' is not in the allowed whitelist."

            # 3. Check Network Scope
            if binary_name in self.NETWORK_TOOLS:
                # Check arguments for network scope
                args = tokens[1:]
                for arg in args:
                    if not self._is_arg_safe(arg):
                        return False, f"Target '{arg}' is out of allowed network scope."

        return True, "Command is safe."

    def _is_arg_safe(self, arg: str) -> bool:
        """Check if a command argument is within the allowed scope."""
        # Strip quotes
        arg = arg.strip("'\"")

        # Ignore options/flags
        if arg.startswith("-"):
            return True

        # Check if IP
        try:
            ip = ipaddress.ip_address(arg)
            return any(ip in net for net in self.ALLOWED_NETWORKS)
        except ValueError:
            pass  # Not an IP

        # Check if Domain-like (has dot, no slash)
        if '.' in arg and '/' not in arg:
            if arg == "localhost":
                return True
            if any(arg.endswith(suffix) for suffix in self.ALLOWED_DOMAINS):
                return True
            return False  # Domain-like but not whitelisted

        # Safe (e.g. port number, file path with slash, plain string)
        return True