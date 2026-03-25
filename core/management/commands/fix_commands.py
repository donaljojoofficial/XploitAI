from django.core.management.base import BaseCommand
from core.models import Command as CommandModel


class Command(BaseCommand):
    help = "Fix broken command templates (dirsearch.py, paramspider.py, whatweb)."

    def handle(self, *args, **options):
        self._fix("EndpointDiscovery", self._endpoint_discovery())
        self._fix("ParameterDiscovery", self._parameter_discovery())
        self._fix("TechnologyFingerprint", self._technology_fingerprint())
        self.stdout.write(self.style.SUCCESS("Done."))

    def _fix(self, name, template):
        count = CommandModel.objects.filter(name=name).update(command_template=template)
        if count:
            self.stdout.write(self.style.SUCCESS(f"  Fixed: {name}"))
        else:
            self.stdout.write(self.style.WARNING(f"  Not found: {name}"))

    def _endpoint_discovery(self):
        lines = [
            "import urllib.request, urllib.error",
            "base = '{target}'.rstrip('/')",
            "paths = ['admin','login','register','api','api/v1','api/users',",
            "    'dashboard','config','backup','.env','robots.txt',",
            "    'sitemap.xml','wp-admin','phpmyadmin','health','status',",
            "    'swagger','docs','upload','uploads']",
            "print('Endpoint discovery: ' + base)",
            "for path in paths:",
            "    url = base + '/' + path",
            "    try:",
            "        req = urllib.request.Request(",
            "            url, headers={'User-Agent': 'XploitAI-Scanner'}, method='HEAD')",
            "        resp = urllib.request.urlopen(req, timeout=5)",
            "        print('  FOUND [' + str(resp.status) + ']: ' + url)",
            "        resp.close()",
            "    except urllib.error.HTTPError as e:",
            "        if e.code not in (404, 410):",
            "            print('  [' + str(e.code) + ']: ' + url)",
            "    except Exception:",
            "        pass",
        ]
        code = "\n".join(lines)
        return "python -c \"exec('''{}''')\"".format(code.replace("'", "\\'"))

    def _parameter_discovery(self):
        lines = [
            "import urllib.request, urllib.error",
            "base = '{target}'.rstrip('/')",
            "endpoints = [base+'/login', base+'/api', base+'/search']",
            "params = ['id=1','user=admin','debug=1','test=1','page=1','q=test']",
            "print('Parameter probe: ' + base)",
            "for ep in endpoints:",
            "    for p in params:",
            "        url = ep + '?' + p",
            "        try:",
            "            req = urllib.request.Request(",
            "                url, headers={'User-Agent': 'XploitAI-Scanner'})",
            "            resp = urllib.request.urlopen(req, timeout=5)",
            "            print('  [' + str(resp.status) + ']: ' + url)",
            "            resp.close()",
            "        except urllib.error.HTTPError as e:",
            "            if e.code not in (404, 410):",
            "                print('  [' + str(e.code) + ']: ' + url)",
            "        except Exception:",
            "            pass",
        ]
        code = "\n".join(lines)
        return "python -c \"exec('''{}''')\"".format(code.replace("'", "\\'"))

    def _technology_fingerprint(self):
        lines = [
            "import sys, re",
            "body = sys.stdin.read()",
            "techs = {",
            "    'WordPress': 'wp-content', 'Joomla': 'joomla', 'Drupal': 'Drupal',",
            "    'PHP': 'php', 'jQuery': 'jquery', 'Bootstrap': 'bootstrap',",
            "    'React': 'react', 'Angular': 'angular', 'Vue': 'vue',",
            "}",
            "for k, v in techs.items():",
            "    if re.search(v, body, re.I):",
            "        print('TECH_FOUND: ' + k)",
            "meta = re.findall(r'<meta[^>]+generator[^>]+>', body, re.I)",
            "for m in meta[:5]:",
            "    print('META_GENERATOR: ' + m)",
        ]
        code = "\n".join(lines)
        pipe_code = "python -c \"exec('''{}''')\"".format(code.replace("'", "\\'"))
        return "curl -sL -m 20 --user-agent \"XploitAI-Scanner\" {target} | " + pipe_code