import re

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
        # whatweb output is complex; we'll do simple keyword matching for demo
        tech = []
        if "Apache" in output:
            tech.append("Apache")
        if "PHP" in output:
            tech.append("PHP")
        if "jQuery" in output:
            tech.append("jQuery")
        if tech:
            findings["identified_technologies"] = list(set(tech))

    elif action_name == "PassiveRecon":
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", output)
        if ips:
            findings["resolved_ips"] = list(set(ips))

    return findings