import re
import json


def merge_findings(primary: dict, secondary: dict) -> dict:
    """Merge parser and AI findings while preserving lists and nested dicts."""
    merged = dict(primary or {})
    for key, value in (secondary or {}).items():
        if key not in merged:
            merged[key] = value
            continue

        current = merged[key]
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = merge_findings(current, value)
            continue

        if isinstance(current, list) and isinstance(value, list):
            seen = {json.dumps(item, sort_keys=True, default=str) for item in current}
            for item in value:
                fingerprint = json.dumps(item, sort_keys=True, default=str)
                if fingerprint not in seen:
                    current.append(item)
                    seen.add(fingerprint)
            merged[key] = current
            continue

        if current in (None, "", [], {}) and value not in (None, "", [], {}):
            merged[key] = value

    return merged


def is_meaningful_action_success(action_name: str, findings: dict, stdout: str) -> bool:
    """Return True only when an action produced evidence that fulfills its purpose."""
    findings = findings or {}
    text = stdout or ""
    lowered_text = text.lower()

    if action_name == "ExploitAttempt":
        return bool(
            findings.get("valid_credentials")
            or findings.get("session_cookies")
            or findings.get("exploit_research_completed")
        )

    if action_name == "ProofOfCompromise":
        return bool(findings.get("proof_of_compromise") or _has_exposed_proof_evidence(findings))
    if action_name == "PayloadGeneration":
        return bool(findings.get("payload_generated"))
    if action_name == "ExploitScriptGeneration":
        return bool(findings.get("generated_script"))

    if action_name == "SQLInjectionProbe":
        return bool(findings.get("sqli_signals"))

    if action_name == "VulnerabilityScanning":
        return bool(
            findings.get("missing_security_headers")
            or findings.get("exposed_paths")
            or findings.get("suspicious_paths")
            or findings.get("scan_completed")
            or _has_completed_scan_output(lowered_text)
        )

    if action_name in {"EndpointDiscovery", "EndpointProbe"}:
        return bool(findings.get("discovered_endpoints")) or (
            (
                "probing:" in lowered_text
                or "endpoint discovery:" in lowered_text
                or ("starting nmap" in lowered_text and "extensions:" in lowered_text)
            )
            and "error:" not in lowered_text
            and "scan_error:" not in lowered_text
        )

    if action_name == "ParameterDiscovery":
        return bool(findings.get("discovered_parameters")) or (
            "parameter probe:" in lowered_text
            and "error:" not in lowered_text
            and "scan_error:" not in lowered_text
        )

    return "ERROR:" not in text and "SCAN_ERROR:" not in text


def has_attack_completion_evidence(findings: dict) -> bool:
    findings = findings or {}
    return bool(
        findings.get("proof_of_compromise")
        or findings.get("valid_credentials")
        or findings.get("session_cookies")
        or findings.get("sqli_signals")
        or _has_exposed_proof_evidence(findings)
    )


def _has_exposed_proof_evidence(findings: dict) -> bool:
    exposed = findings.get("exposed_paths")
    if not isinstance(exposed, list):
        return False
    proof_markers = ("phpinfo", "php version", "configuration", "server api", "loaded configuration")
    for item in exposed:
        if isinstance(item, dict):
            text = f"{item.get('path', '')} {item.get('evidence', '')}".lower()
        else:
            text = str(item or "").lower()
        if any(marker in text for marker in proof_markers):
            return True
    return False

def parse_output(action_name: str, output: str) -> dict:
    """
    Parses raw command output into structured findings based on the action.
    """
    findings = {}

    if action_name == "HTTPHeaderFetch":
        server_match = re.search(r"Server:\s*(.*)", output, re.IGNORECASE)
        if server_match:
            findings["server_banner"] = server_match.group(1).strip()

        x_powered_by_match = re.search(r"X-Powered-By:\s*(.*)", output, re.IGNORECASE)
        if x_powered_by_match:
            findings["x_powered_by"] = x_powered_by_match.group(1).strip()

    elif action_name == "TechnologyFingerprint":
        tech = []
        for marker in re.findall(r"TECH_FOUND:\s*([^\r\n]+)", output):
            tech.append(marker.strip())
        for marker in re.findall(r"META_GENERATOR:\s*([^\r\n]+)", output):
            tech.append(marker.strip())
        if tech:
            findings["identified_technologies"] = list(set(tech))

    elif action_name in {"EndpointDiscovery", "EndpointProbe"}:
        endpoints = []
        for match in re.findall(r"(?:FOUND|\[\d+\]):\s*(https?://[^\s]+)", output):
            endpoints.append(match.strip())
        if endpoints:
            findings["discovered_endpoints"] = sorted(set(endpoints))

    elif action_name == "ParameterDiscovery":
        params = []
        urls = re.findall(r"(https?://[^\s]+)", output)
        for url in urls:
            if "?" in url:
                query = url.split("?", 1)[1]
                for token in query.split("&"):
                    key = token.split("=", 1)[0].strip()
                    if key:
                        params.append(key)
        if params:
            findings["discovered_parameters"] = sorted(set(params))

    elif action_name == "VulnerabilityScanning":
        missing_headers = re.findall(r"HEADER_MISSING:\s*([^\r\n]+)", output)
        exposed_paths = re.findall(r"EXPOSED_PATH:\s*([^\s]+)\s*=>\s*([^\r\n]+)", output)
        suspicious_paths = re.findall(r"SUSPICIOUS_PATH:\s*([^\s]+)\s*status=([^\r\n]+)", output)
        server_banner = re.search(r"SERVER_BANNER:\s*([^\r\n]+)", output)
        powered_by = re.search(r"POWERED_BY:\s*([^\r\n]+)", output)
        if missing_headers:
            findings["missing_security_headers"] = sorted(set(h.strip() for h in missing_headers))
        if exposed_paths:
            findings["exposed_paths"] = [
                {"path": path.strip(), "evidence": evidence.strip()}
                for path, evidence in exposed_paths
            ]
        if suspicious_paths:
            findings["suspicious_paths"] = [
                {"path": path.strip(), "status": status.strip()}
                for path, status in suspicious_paths
            ]
        if server_banner:
            findings["server_banner"] = server_banner.group(1).strip()
        if powered_by:
            findings["x_powered_by"] = powered_by.group(1).strip()
        if _has_completed_scan_output((output or "").lower()):
            findings["scan_completed"] = True

    elif action_name == "SQLInjectionProbe":
        sqli_signals = re.findall(r"SQLI_SIGNAL:\s*([^\r\n]+)", output)
        if sqli_signals:
            findings["sqli_signals"] = [signal.strip() for signal in sqli_signals]

    elif action_name == "ExploitAttempt":
        if "EXPLOIT_RESEARCH_COMPLETE" in (output or ""):
            findings["exploit_research_completed"] = True
        auth_success = re.findall(
            r"AUTH_SUCCESS:\s*([^\s]+)\s+user=([^\s]+)\s+password=([^\r\n]+)",
            output,
        )
        credential_success = re.findall(
            r"SUCCESSFUL_CREDENTIAL:\s*path=([^\s]+)\s+username=([^\s]+)\s+password=([^\r\n]+)",
            output,
        )
        session_cookies = re.findall(r"SESSION_COOKIE:\s*([^\r\n]+)", output)
        redirects = re.findall(r"REDIRECT_TARGET:\s*([^\r\n]+)", output)
        successful_login_urls = re.findall(r"SUCCESSFUL_LOGIN_URL:\s*([^\r\n]+)", output)
        if auth_success or credential_success:
            seen_credentials = set()
            valid_credentials = []
            for path, username, password in [*auth_success, *credential_success]:
                item = (path.strip(), username.strip(), password.strip())
                if item in seen_credentials:
                    continue
                seen_credentials.add(item)
                valid_credentials.append({"path": item[0], "username": item[1], "password": item[2]})
            findings["valid_credentials"] = [
                credential
                for credential in valid_credentials
            ]
        if session_cookies:
            findings["session_cookies"] = [cookie.strip() for cookie in session_cookies]
        if redirects:
            findings["redirect_targets"] = [target.strip() for target in redirects]
        if successful_login_urls:
            findings["successful_login_urls"] = [url.strip() for url in successful_login_urls]

    elif action_name == "ProofOfCompromise":
        if "NO_HASH_FILE:" in (output or "") or "NO_CREDENTIAL_LOOT:" in (output or ""):
            findings["missing_credential_loot"] = True
        proofs = re.findall(r"PROOF_FOUND:\s*([^\s]+)\s*=>\s*([^\r\n]+)", output)
        proof_summary = re.search(r"PROOF_SUMMARY:\s*([^\r\n]+)", output)
        if proofs:
            findings["proof_of_compromise"] = [
                {"path": path.strip(), "evidence": evidence.strip()}
                for path, evidence in proofs
            ]
        if proof_summary:
            findings["proof_summary"] = proof_summary.group(1).strip()

    elif action_name == "PayloadGeneration":
        if "PAYLOAD_GENERATED" in (output or ""):
            findings["payload_generated"] = True
        payload_json = re.search(r"\[(?:.|\n)*\]", output or "")
        if payload_json:
            try:
                findings["payload_items"] = json.loads(payload_json.group(0))
            except Exception:
                pass

    elif action_name == "ExploitScriptGeneration":
        if "SCRIPT_GENERATED" in (output or ""):
            findings["generated_script"] = True
        script_lines = []
        found = False
        for line in (output or "").splitlines():
            if found:
                script_lines.append(line)
            elif line.strip() == "SCRIPT_GENERATED":
                found = True
        if script_lines:
            findings["generated_script_preview"] = "\n".join(script_lines[:40])

    elif action_name == "PassiveRecon":
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", output)
        if ips:
            findings["resolved_ips"] = list(set(ips))

    return findings


def _has_completed_scan_output(lowered_text: str) -> bool:
    if not lowered_text:
        return False
    fatal_markers = (
        "command not found",
        "not recognized as an internal or external command",
        "execution timed out",
        "traceback",
    )
    if any(marker in lowered_text for marker in fatal_markers):
        return False
    scan_markers = (
        "nikto v",
        "+ target ip:",
        "+ target hostname:",
        "+ target port:",
        "+ server:",
        "+ scan terminated:",
        "nuclei",
        "[inf]",
        "[wrn]",
    )
    return any(marker in lowered_text for marker in scan_markers)
