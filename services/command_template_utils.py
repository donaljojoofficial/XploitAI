from __future__ import annotations

import re

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
    template = command_obj.command_template or ""
    canonical = CANONICAL_TEMPLATES.get(command_obj.name)
    if not template and canonical:
        command_obj.command_template = canonical
        command_obj.save(update_fields=["command_template"])
        return canonical

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
