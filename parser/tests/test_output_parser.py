from django.test import SimpleTestCase

from parser.output_parser import is_meaningful_action_success


class OutputParserSuccessTests(SimpleTestCase):
    def test_parameter_discovery_probe_banner_counts_as_success_without_findings(self):
        stdout = "Parameter probe: http://127.0.0.1:4280/\n"

        self.assertTrue(is_meaningful_action_success("ParameterDiscovery", {}, stdout))

    def test_parameter_discovery_scan_error_still_counts_as_failure(self):
        stdout = "Parameter probe: http://127.0.0.1:4280/\nSCAN_ERROR: timeout\n"

        self.assertFalse(is_meaningful_action_success("ParameterDiscovery", {}, stdout))

    def test_endpoint_discovery_probe_banner_counts_as_success_without_findings(self):
        stdout = "Probing: http://127.0.0.1:4280/\n"

        self.assertTrue(is_meaningful_action_success("EndpointDiscovery", {}, stdout))

    def test_endpoint_discovery_nmap_and_dirsearch_output_counts_as_success_without_hits(self):
        stdout = (
            "Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-28 23:46 +0530\n"
            "Nmap scan report for localhost (127.0.0.1)\n"
            "Host is up (0.00013s latency).\n"
            "PORT     STATE SERVICE\n"
            "4280/tcp open  vrml-multi-use\n"
            "Nmap done: 1 IP address (1 host up) scanned in 0.60 seconds\n"
            "Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25\n"
            "Wordlist size: 4\n"
        )

        self.assertTrue(is_meaningful_action_success("EndpointDiscovery", {}, stdout))
