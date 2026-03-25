from django.test import SimpleTestCase

from services.command_template_utils import escape_non_placeholder_braces


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
