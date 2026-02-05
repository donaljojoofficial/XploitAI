"""
AI Command Generator — XploitAI

Responsibilities:
- Translate high-level ActionProposals into executable shell commands.
- Ensure commands are syntactically valid and safe.
- Integrate with LLM for dynamic command generation when enabled.

This module is the bridge between "What to do" (Decision) and "How to do it" (Execution).
"""

from __future__ import annotations

import logging
import re
import shlex
from typing import Any, Mapping, Optional

# Attempt to import the LLM adapter (Phase 3/Auto feature)
try:
    from ai.llm.gemini import GeminiAdapter
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

logger = logging.getLogger(__name__)


class CommandGenerator:
    """
    Generates shell commands from abstract actions.
    Supports both rule-based generation (deterministic) and LLM-based generation (dynamic).
    """

    def __init__(self, use_llm: bool = True) -> None:
        """
        Initialize the command generator.

        Args:
            use_llm: Whether to attempt using the LLM for generation.
                     Automatically falls back to rule-based if LLM is unavailable.
        """
        self.use_llm = use_llm and LLM_AVAILABLE
        self.llm_client = None

        if self.use_llm:
            try:
                self.llm_client = GeminiAdapter()
                logger.info("CommandGenerator initialized with LLM support (Gemini).")
            except Exception as e:
                logger.warning("Failed to initialize LLM adapter: %s. Reverting to rule-based.", e)
                self.use_llm = False

    def generate(self, action_name: str, parameters: Mapping[str, Any]) -> str:
        """
        Generate a shell command for the given action.

        Args:
            action_name: The name of the action (e.g., 'ServiceEnumeration').
            parameters: Dictionary of parameters for the action.

        Returns:
            str: The executable shell command.
        """
        logger.debug("Generating command for action: %s", action_name)

        # 1. Try LLM Generation if enabled
        if self.use_llm:
            try:
                command = self._generate_with_llm(action_name, parameters)
                if command:
                    return command
            except Exception as e:
                logger.error("LLM generation failed for '%s': %s. Falling back to rules.", action_name, e)

        # 2. Fallback to Rule-Based Generation
        return self._generate_rule_based(action_name, parameters)

    def _generate_rule_based(self, action_name: str, parameters: Mapping[str, Any]) -> str:
        """Dispatch to specific rule-based generators."""
        if action_name == "PassiveRecon":
            return self._generate_passive_recon(parameters)
        elif action_name == "ServiceEnumeration":
            return self._generate_service_enumeration(parameters)
        elif action_name == "ExploitAttempt":
            return self._generate_exploit_attempt(parameters)
        elif action_name == "PrivilegeEscalation":
            return self._generate_privilege_escalation(parameters)
        elif action_name == "ProofOfCompromise":
            return self._generate_proof_of_compromise(parameters)
        else:
            logger.warning("Unknown action '%s'. Returning fallback echo.", action_name)
            return f"echo 'Unknown action: {shlex.quote(action_name)}'"

    def _generate_with_llm(self, action_name: str, parameters: Mapping[str, Any]) -> Optional[str]:
        """Generate command using the LLM."""
        if not self.llm_client:
            return None

        prompt = self._construct_prompt(action_name, parameters)

        # Assuming the adapter has a 'generate' method based on common patterns
        response = self.llm_client.generate(prompt)

        if not response:
            return None

        return self._extract_command(response)

    def _construct_prompt(self, action_name: str, parameters: Mapping[str, Any]) -> str:
        """Construct the prompt for the LLM."""
        safe_params = {k: str(v) for k, v in parameters.items()}
        return (
            f"You are an autonomous red team operator.\n"
            f"Generate a single, valid shell command for the following action.\n"
            f"Target OS: Linux (Kali/Debian).\n\n"
            f"Action: {action_name}\n"
            f"Parameters: {safe_params}\n\n"
            f"Constraints:\n"
            f"- Return ONLY the shell command.\n"
            f"- Do not use markdown formatting unless wrapping code.\n"
            f"- No explanations.\n"
            f"- Use standard tools (nmap, whois, netcat, curl, etc.).\n"
            f"- Ensure the command is non-interactive.\n"
        )

    def _extract_command(self, text: str) -> str:
        """Extract the command from LLM response (handling markdown)."""
        match = re.search(r'```(?:bash|sh)?\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()

    def _generate_passive_recon(self, params: Mapping[str, Any]) -> str:
        domain = params.get("target_domain", "localhost")
        safe_domain = shlex.quote(str(domain))
        # Example recon chain
        return f"whois {safe_domain} && nslookup {safe_domain}"

    def _generate_service_enumeration(self, params: Mapping[str, Any]) -> str:
        host = params.get("target_host", "localhost")
        safe_host = shlex.quote(str(host))
        # Standard service scan
        return f"nmap -sV -T4 {safe_host}"

    def _generate_exploit_attempt(self, params: Mapping[str, Any]) -> str:
        host = params.get("target_host", "localhost")
        vuln_id = params.get("vulnerability_id", "unknown")
        safe_host = shlex.quote(str(host))
        safe_vuln = shlex.quote(str(vuln_id))
        # Simulation placeholder: In Phase 2/3 this would invoke a specific exploit script
        return f"echo 'Exploiting {safe_host} using {safe_vuln}'"

    def _generate_privilege_escalation(self, params: Mapping[str, Any]) -> str:
        host = params.get("target_host", "localhost")
        safe_host = shlex.quote(str(host))
        # Simulation placeholder
        return f"echo 'Attempting privilege escalation on {safe_host}'"

    def _generate_proof_of_compromise(self, params: Mapping[str, Any]) -> str:
        tag = params.get("evidence_tag", "proof")
        safe_tag = shlex.quote(str(tag))
        return f"echo 'PROOF_OF_COMPROMISE: {safe_tag}' > /tmp/proof.txt"
