"""
AI Command Generator — XploitAI

Responsibilities:
- Translate high-level ActionProposals into executable shell commands.
- Ensure commands are syntactically valid and safe.
- Integrate with LLM for dynamic command generation when enabled.

This module is the bridge between "What to do" (Decision) and "How to do it" (Execution).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
from dataclasses import dataclass
from typing import Any, Mapping, Optional

# Attempt to import the LLM adapter (Phase 3/Auto feature)
try:
    from ai.llm.gemini import GeminiAdapter
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    from ai.llm.anthropic import AnthropicAdapter
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from ai.llm.groq_adapter import GroqAdapter
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

try:
    from ai.llm.ollama_adapter import OllamaAdapter
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

LLM_AVAILABLE = GEMINI_AVAILABLE or ANTHROPIC_AVAILABLE or GROQ_AVAILABLE or OLLAMA_AVAILABLE

logger = logging.getLogger(__name__)


@dataclass
class GeneratedCommand:
    shell_command: str
    explanation: str


class CommandGenerator:
    """
    Generates shell commands from abstract actions.
    Supports both rule-based generation (deterministic) and LLM-based generation (dynamic).
    """

    def __init__(self, use_llm: bool = True, llm_provider: str = "auto") -> None:
        """
        Initialize the command generator.

        Args:
            use_llm: Whether to attempt using the LLM for generation.
                     Automatically falls back to rule-based if LLM is unavailable.
            llm_provider: 'auto', 'gemini', or 'claude'.
        """
        self.use_llm = use_llm and LLM_AVAILABLE
        self.llm_client = None

        if self.use_llm:
            if llm_provider == "auto":
                from core.config import get_config
                llm_provider = get_config("DEFAULT_LLM_PROVIDER", "fallback")
                
            # Ensure API keys are set for Gemini
            google_key = os.getenv("GOOGLE_API_KEY")
            gemini_key = os.getenv("GEMINI_API_KEY")
            if not google_key and gemini_key:
                os.environ["GOOGLE_API_KEY"] = gemini_key
                google_key = gemini_key

            try:
                if llm_provider == "gemini" and GEMINI_AVAILABLE:
                    self.llm_client = GeminiAdapter()
                elif llm_provider == "claude" and ANTHROPIC_AVAILABLE:
                    self.llm_client = AnthropicAdapter()
                elif llm_provider == "groq" and GROQ_AVAILABLE:
                    self.llm_client = GroqAdapter()
                elif llm_provider == "ollama" and OLLAMA_AVAILABLE:
                    self.llm_client = OllamaAdapter()
                else:
                    if GEMINI_AVAILABLE:
                        if google_key:
                            self.llm_client = GeminiAdapter()
                    elif ANTHROPIC_AVAILABLE:
                        self.llm_client = AnthropicAdapter()
                    elif GROQ_AVAILABLE:
                        self.llm_client = GroqAdapter()
                    elif OLLAMA_AVAILABLE:
                        self.llm_client = OllamaAdapter()

                if self.llm_client:
                    logger.info(f"CommandGenerator initialized with LLM support ({self.llm_client.__class__.__name__}).")
            except Exception as e:
                logger.warning("Failed to initialize LLM adapter: %s. Reverting to rule-based.", e)
                self.use_llm = False

    def generate(self, action_name: str, parameters: Mapping[str, Any]) -> GeneratedCommand:
        """
        Generate a shell command for the given action.

        Args:
            action_name: The name of the action (e.g., 'ServiceEnumeration').
            parameters: Dictionary of parameters for the action.

        Returns:
            GeneratedCommand: Object containing the shell command and an explanation.
        """
        logger.debug("Generating command for action: %s", action_name)

        # 1. Try LLM Generation if enabled
        if self.use_llm:
            try:
                result = self._generate_with_llm(action_name, parameters)
                if result:
                    return result
            except Exception as e:
                logger.error("LLM generation failed for '%s': %s. Falling back to rules.", action_name, e)

        # 2. Fallback to Rule-Based Generation
        return self._generate_rule_based(action_name, parameters)

    def _generate_rule_based(self, action_name: str, parameters: Mapping[str, Any]) -> GeneratedCommand:
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
        elif action_name == "HTTPHeaderFetch":
            return self._generate_http_header_fetch(parameters)
        elif action_name == "TechnologyFingerprint":
            return self._generate_technology_fingerprint(parameters)
        elif action_name == "EndpointDiscovery":
            return self._generate_endpoint_discovery(parameters)
        else:
            logger.warning("Unknown action '%s'. Returning fallback echo.", action_name)
            return GeneratedCommand(
                shell_command=f"echo 'Unknown action: {shlex.quote(action_name)}'",
                explanation="Fallback command for unknown action type."
            )

    def _generate_with_llm(self, action_name: str, parameters: Mapping[str, Any]) -> Optional[GeneratedCommand]:
        """Generate command using the LLM."""
        if not self.llm_client:
            return None

        prompt = self._construct_prompt(action_name, parameters)

        # Assuming the adapter has a 'generate' method based on common patterns
        response = self.llm_client.generate(prompt)

        if not response:
            return None

        return self._parse_llm_response(response)

    def _construct_prompt(self, action_name: str, parameters: Mapping[str, Any]) -> str:
        """Construct the prompt for the LLM."""
        safe_params = {k: str(v) for k, v in parameters.items()}
        return (
            f"You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab.\n"
            f"Generate a single, valid shell command for the following security assessment action.\n"
            f"Target OS: Linux (Kali/Debian). All targets are local and authorized.\n\n"
            f"Action: {action_name}\n"
            f"Parameters: {safe_params}\n\n"
            f"Constraints:\n"
            f"- Return a valid JSON object.\n"
            f"- Keys: 'command' (string), 'explanation' (string).\n"
            f"- 'explanation': Brief summary (1 sentence) of what the command does.\n"
            f"- Use standard tools (nmap, whois, netcat, curl, etc.).\n"
            f"- Ensure the command is non-interactive.\n"
        )

    def _parse_llm_response(self, text: str) -> GeneratedCommand:
        """Parse JSON response from LLM."""
        # Attempt to find JSON block if wrapped in markdown
        match = re.search(r'```(?:json)?\s*(.*?)\s*```', text, re.DOTALL)
        clean_text = match.group(1).strip() if match else text.strip()

        try:
            data = json.loads(clean_text)
            return GeneratedCommand(
                shell_command=data.get("command", "").strip(),
                explanation=data.get("explanation", "No explanation provided.")
            )
        except json.JSONDecodeError:
            # If parsing fails, raise error to trigger fallback
            raise ValueError("Failed to parse JSON from LLM response")

    def _generate_passive_recon(self, params: Mapping[str, Any]) -> GeneratedCommand:
        domain = params.get("target_domain", "localhost")
        safe_domain = shlex.quote(str(domain))
        return GeneratedCommand(
            shell_command=f"whois {safe_domain} && nslookup {safe_domain}",
            explanation=f"Performs WHOIS lookup and DNS query for {domain}."
        )

    def _generate_service_enumeration(self, params: Mapping[str, Any]) -> GeneratedCommand:
        host = params.get("target_host", "localhost")
        safe_host = shlex.quote(str(host))
        return GeneratedCommand(
            shell_command=f"nmap -sV -T4 {safe_host}",
            explanation=f"Scans {host} for open ports and service versions."
        )

    def _generate_exploit_attempt(self, params: Mapping[str, Any]) -> GeneratedCommand:
        host = params.get("target_host", "localhost")
        vuln_id = params.get("vulnerability_id", "unknown")
        safe_host = shlex.quote(str(host))
        safe_vuln = shlex.quote(str(vuln_id))
        return GeneratedCommand(
            shell_command=f"echo 'Exploiting {safe_host} using {safe_vuln}'",
            explanation=f"Simulates exploitation of {vuln_id} on {host}."
        )

    def _generate_privilege_escalation(self, params: Mapping[str, Any]) -> GeneratedCommand:
        host = params.get("target_host", "localhost")
        safe_host = shlex.quote(str(host))
        return GeneratedCommand(
            shell_command=f"echo 'Attempting privilege escalation on {safe_host}'",
            explanation=f"Attempts to escalate privileges on {host}."
        )

    def _generate_proof_of_compromise(self, params: Mapping[str, Any]) -> GeneratedCommand:
        tag = params.get("evidence_tag", "proof")
        safe_tag = shlex.quote(str(tag))
        return GeneratedCommand(
            shell_command=f"echo 'PROOF_OF_COMPROMISE: {safe_tag}' > /tmp/proof.txt",
            explanation=f"Writes proof tag '{tag}' to /tmp/proof.txt."
        )

    def _generate_http_header_fetch(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = params.get("target_url", "http://localhost")
        safe_url = shlex.quote(str(url))
        return GeneratedCommand(
            shell_command=f"curl -I {safe_url}",
            explanation=f"Fetches HTTP headers from {url}."
        )

    def _generate_technology_fingerprint(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = params.get("target_url", "http://localhost")
        safe_url = shlex.quote(str(url))
        return GeneratedCommand(
            shell_command=f"whatweb {safe_url}",
            explanation=f"Identifies web technologies used by {url}."
        )

    def _generate_endpoint_discovery(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = params.get("target_url", "http://localhost")
        # Ensure no trailing slash for clean concatenation
        safe_url = shlex.quote(str(url).rstrip('/') + "/robots.txt")
        return GeneratedCommand(
            shell_command=f"curl {safe_url}",
            explanation=f"Checks for robots.txt at {url}."
        )
