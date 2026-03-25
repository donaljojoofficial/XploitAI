from __future__ import annotations

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


def normalize_command_template(command_obj: Command) -> str:
    """
    Replace legacy external-tool templates with built-in safe equivalents.
    Persists the repaired template so old DB rows self-heal over time.
    """
    template = command_obj.command_template or ""
    canonical = CANONICAL_TEMPLATES.get(command_obj.name)
    if not canonical:
        return template

    legacy_markers = (
        "python dirsearch.py",
        "python paramspider.py",
        "whatweb ",
        "grep -iE 'generator|wordpress|joomla|drupal|php'",
    )
    if template == canonical:
        return template
    if any(marker in template for marker in legacy_markers):
        command_obj.command_template = canonical
        command_obj.save(update_fields=["command_template"])
        return canonical

    return template
