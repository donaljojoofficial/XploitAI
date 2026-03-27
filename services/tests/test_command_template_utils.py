from django.test import SimpleTestCase

from services.command_template_utils import (
    escape_non_placeholder_braces,
    normalize_command_template,
    render_command_template,
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
