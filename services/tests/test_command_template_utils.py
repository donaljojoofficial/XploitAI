from django.test import SimpleTestCase

from services.command_template_utils import (
    build_target_context,
    escape_non_placeholder_braces,
    infer_required_tools,
    is_probable_shell_command,
    normalize_command_targets,
    normalize_command_template,
    render_command_template,
    split_chained_tool_command,
    uses_placeholder_loot_path,
)


class CommandTemplateUtilsTests(SimpleTestCase):
    def test_escapes_inline_dict_braces_but_preserves_known_placeholders(self):
        template = (
            "python -c \"req = urllib.request.Request("
            "url, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\" "
            "{target}"
        )

        escaped = escape_non_placeholder_braces(template)
        rendered = escaped.format(target="http://127.0.0.1:4280/")

        self.assertIn("{'User-Agent': 'XploitAI-Scanner/1.0'}", rendered)
        self.assertIn("http://127.0.0.1:4280/", rendered)

    def test_normalize_does_not_persist_escaped_template(self):
        command = type(
            "CommandStub",
            (),
            {
                "name": "EndpointDiscovery",
                "command_template": (
                    "python -c \"req = urllib.request.Request("
                    "url, headers={'User-Agent': 'XploitAI-Scanner/1.0'})\" {target}"
                ),
                "save": lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("save should not be called")),
            },
        )()

        normalized = normalize_command_template(command)

        self.assertIn("{{'User-Agent': 'XploitAI-Scanner/1.0'}}", normalized)
        self.assertIn("{target}", normalized)
        self.assertIn("{'User-Agent': 'XploitAI-Scanner/1.0'}", command.command_template)

    def test_render_collapses_single_escape_layer_without_brace_explosion(self):
        template = (
            "python -c \"patterns={{'WordPress':'wp-content'}}; "
            "req = urllib.request.Request(url, headers={{'User-Agent': 'XploitAI-Scanner/1.0'}})\" "
            "{target}"
        )

        rendered = render_command_template(
            template,
            {"target": "http://127.0.0.1:4280/"},
        )

        self.assertIn("patterns={'WordPress':'wp-content'}", rendered)
        self.assertIn("headers={'User-Agent': 'XploitAI-Scanner/1.0'}", rendered)
        self.assertNotIn("{{{{", rendered)

    def test_build_target_context_extracts_host_from_url(self):
        context = build_target_context("http://127.0.0.1:4280/")

        self.assertEqual(context["target"], "http://127.0.0.1:4280/")
        self.assertEqual(context["target_url"], "http://127.0.0.1:4280/")
        self.assertEqual(context["target_host"], "127.0.0.1")
        self.assertEqual(context["target_domain"], "127.0.0.1")
        self.assertEqual(context["target_port"], "4280")

    def test_normalize_command_targets_rewrites_nmap_url_target(self):
        context = build_target_context("http://127.0.0.1:4280/")

        command = "nmap -sV -p- http://127.0.0.1:4280/ -oX output.xml"

        normalized = normalize_command_targets(command, context)

        self.assertEqual(normalized, "nmap -sV -p- 127.0.0.1 -oX output.xml")

    def test_infer_required_tools_detects_shell_dependencies(self):
        tools = infer_required_tools("curl -s http://127.0.0.1:4280/ | jq '.'")

        self.assertEqual(tools, ["curl", "jq"])

    def test_split_chained_tool_command_keeps_quoted_semicolons_intact(self):
        command = (
            "searchsploit PHP && "
            "sqlmap -u 'http://127.0.0.1:4280/search?q=test' --batch && "
            "msfconsole -q -x \"search 127.0.0.1; exit -y\""
        )

        parts = split_chained_tool_command(command)

        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], "searchsploit PHP")
        self.assertIn("sqlmap -u", parts[1])
        self.assertIn('msfconsole -q -x "search 127.0.0.1; exit -y"', parts[2])

    def test_is_probable_shell_command_rejects_plan_rationale_text(self):
        self.assertTrue(is_probable_shell_command("searchsploit PHP"))
        self.assertTrue(is_probable_shell_command("msfconsole -q -x \"search 127.0.0.1; exit -y\""))
        self.assertFalse(
            is_probable_shell_command(
                "Access exposed /phpinfo.php to extract PHP configuration details for potential vulnerabilities."
            )
        )

    def test_uses_placeholder_loot_path_detects_fake_hash_defaults(self):
        self.assertTrue(uses_placeholder_loot_path("john --show /tmp/loot.hashes"))
        self.assertTrue(uses_placeholder_loot_path("hashcat --show /tmp/loot.hashes"))
        self.assertFalse(uses_placeholder_loot_path("john --show /tmp/real.hashes"))
