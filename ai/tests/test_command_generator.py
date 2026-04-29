from django.test import SimpleTestCase

from ai.command_generator import CommandGenerator
from ai.llm.local_rule_engine import LocalRuleEngine


class CommandGeneratorTests(SimpleTestCase):
    def test_rule_only_mode_skips_llm_router_initialization(self):
        generator = CommandGenerator(use_llm=False, llm_provider="auto")

        self.assertIsInstance(generator.llm_client, LocalRuleEngine)

    def test_rule_based_generation_uses_phase_appropriate_tools(self):
        generator = CommandGenerator(use_llm=False, llm_provider="auto")

        recon = generator.generate("PassiveRecon", {"target_domain": "example.com"})
        endpoint = generator.generate("EndpointDiscovery", {"target_url": "http://127.0.0.1:4280/"})
        params = generator.generate("ParameterDiscovery", {"target_url": "http://127.0.0.1:4280/"})
        vuln = generator.generate("VulnerabilityScanning", {"target_url": "http://127.0.0.1:4280/"})
        sqli = generator.generate("SQLInjectionProbe", {"target_url": "http://127.0.0.1:4280/"})
        exploit = generator.generate("ExploitAttempt", {"target_url": "http://127.0.0.1:4280/", "tech": "php"})
        post = generator.generate("ProofOfCompromise", {"hash_file": "/tmp/example.hash"})
        proof_without_hash = generator.generate("ProofOfCompromise", {"target_url": "http://127.0.0.1:4280/"})
        proof_from_phpinfo = generator.generate(
            "ProofOfCompromise",
            {"target_url": "http://127.0.0.1:4280/", "proof_path": "/phpinfo.php"},
        )
        privesc_without_hash = generator.generate("PrivilegeEscalation", {"target_url": "http://127.0.0.1:4280/"})

        self.assertIn("whois", recon.shell_command)
        self.assertIn("dig", recon.shell_command)
        self.assertIn("theHarvester", recon.shell_command)
        self.assertIn("nmap", endpoint.shell_command)
        self.assertIn("nc", endpoint.shell_command)
        self.assertIn("dirsearch", endpoint.shell_command)
        self.assertIn("arjun", params.shell_command)
        self.assertIn("nikto", vuln.shell_command)
        self.assertIn("nuclei", vuln.shell_command)
        self.assertIn("sqlmap", sqli.shell_command)
        self.assertIn("searchsploit", exploit.shell_command)
        self.assertIn("msfconsole", exploit.shell_command)
        self.assertIn("john", post.shell_command)
        self.assertIn("if [ -s /tmp/example.hash ]", post.shell_command)
        self.assertIn("PROOF_FOUND", proof_without_hash.shell_command)
        self.assertIn("http://127.0.0.1:4280/phpinfo.php", proof_from_phpinfo.shell_command)
        self.assertIn("PROOF_FOUND", proof_from_phpinfo.shell_command)
        self.assertIn("NO_CREDENTIAL_LOOT", privesc_without_hash.shell_command)
        self.assertNotIn("/tmp/loot.hashes", privesc_without_hash.shell_command)

    def test_vulnerability_scanning_uses_path_hint_from_step_rationale(self):
        generator = CommandGenerator(use_llm=False, llm_provider="auto")

        root_scan = generator.generate(
            "VulnerabilityScanning",
            {
                "target_url": "http://127.0.0.1:4280/",
                "step_rationale": "Scan for vulnerabilities given missing security headers and PHP 8.5.4 presence.",
            },
        )
        dotfile_scan = generator.generate(
            "VulnerabilityScanning",
            {
                "target_url": "http://127.0.0.1:4280/",
                "step_rationale": "Check .gitattributes for information disclosure or source code leaks.",
            },
        )

        self.assertIn("http://127.0.0.1:4280/", root_scan.shell_command)
        self.assertIn("http://127.0.0.1:4280/.gitattributes", dotfile_scan.shell_command)
        self.assertNotEqual(root_scan.shell_command, dotfile_scan.shell_command)
