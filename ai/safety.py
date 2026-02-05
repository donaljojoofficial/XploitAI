"""
AI Command Safety Filter — XploitAI

Responsibilities:
- Validate AI-generated commands against safety rules.
- Enforce whitelisting of allowed tools.
- Block dangerous patterns and characters.

This module acts as a sandbox guardrail before execution.
"""

import logging
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

        return True, "Command is safe."