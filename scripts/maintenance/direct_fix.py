"""
Run from your XploitAI project root:
    python scripts/maintenance/direct_fix.py

This directly updates the broken command templates in the database.
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
import django

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xploitai.settings")
django.setup()

from core.models import Command as C

ENDPOINT = """python -c "
import urllib.request, urllib.error
base = '{target}'.rstrip('/')
paths = ['admin','login','register','api','api/v1','api/users','dashboard',
         'config','backup','.env','robots.txt','sitemap.xml',
         'wp-admin','phpmyadmin','health','status','swagger','docs']
print('Endpoint discovery: ' + base)
for path in paths:
    url = base + '/' + path
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'XploitAI-Scanner'}, method='HEAD')
        resp = urllib.request.urlopen(req, timeout=5)
        print('  FOUND [' + str(resp.status) + ']: ' + url)
        resp.close()
    except urllib.error.HTTPError as e:
        if e.code not in (404, 410):
            print('  [' + str(e.code) + ']: ' + url)
    except Exception:
        pass
"
"""

PARAMETER = """python -c "
import urllib.request, urllib.error
base = '{target}'.rstrip('/')
endpoints = [base+'/login', base+'/api', base+'/search']
params = ['id=1','user=admin','debug=1','test=1','page=1','q=test']
print('Parameter probe: ' + base)
for ep in endpoints:
    for p in params:
        url = ep + '?' + p
        try:
            req = urllib.request.Request(
                url, headers={'User-Agent': 'XploitAI-Scanner'})
            resp = urllib.request.urlopen(req, timeout=5)
            print('  [' + str(resp.status) + ']: ' + url)
            resp.close()
        except urllib.error.HTTPError as e:
            if e.code not in (404, 410):
                print('  [' + str(e.code) + ']: ' + url)
        except Exception:
            pass
"
"""

TECH = 'curl -sL -m 20 --user-agent "XploitAI-Scanner" {target}'

fixes = {
    "EndpointDiscovery": ENDPOINT.strip(),
    "ParameterDiscovery": PARAMETER.strip(),
    "TechnologyFingerprint": TECH,
}

for name, template in fixes.items():
    n = C.objects.filter(name=name).update(command_template=template)
    print(("FIXED" if n else "NOT FOUND") + ": " + name)

print("Done.")
